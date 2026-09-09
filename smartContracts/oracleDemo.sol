// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

/// ---------------------------------------------------------------------------
/// QWID oracle precompiles
/// ---------------------------------------------------------------------------
/// The QWID chain seals two oracle values into every block header, medianed
/// from staked-node submissions and verified by oracle proofs:
///
///   0x…0100  Price oracle — BTC/USD as the raw consensus int64
///   0x…0101  RAND oracle  — consensus randomness (int64)
///
/// Both are exposed to the EVM as precompiles (core/evm/contracts_qwid.go):
/// input is ignored, the return is one 32-byte word holding the value the
/// block containing YOUR transaction carries. Reading costs a fixed 100 gas.
///
/// SECURITY NOTE on randomness: the RAND value of a block is public the moment
/// the block exists, and the block producer sees it first. NEVER settle a bet
/// with randomness from the same block the bet was placed in. The pattern used
/// below is commit-first: entries close at a chosen block height, and the
/// drawing may only run in a strictly LATER block, whose randomness did not
/// exist when the last entry was committed.
library QwidOracles {
    address constant PRICE_ORACLE = address(0x100);
    address constant RAND_ORACLE  = address(0x101);

    /// @notice BTC/USD as sealed in the current block (raw consensus int64).
    function priceBTCUSD() internal view returns (uint256 price) {
        (bool ok, bytes memory out) = PRICE_ORACLE.staticcall("");
        require(ok && out.length == 32, "price oracle unavailable");
        price = abi.decode(out, (uint256));
        require(price > 0, "price oracle not established yet");
    }

    /// @notice Consensus randomness sealed in the current block.
    function randomness() internal view returns (uint256 rand) {
        (bool ok, bytes memory out) = RAND_ORACLE.staticcall("");
        require(ok && out.length == 32, "rand oracle unavailable");
        rand = abi.decode(out, (uint256));
        require(rand > 0, "rand oracle not established yet");
    }
}

/// ---------------------------------------------------------------------------
/// BtcUpDown — a round-based BTC price-direction game using BOTH oracles.
/// ---------------------------------------------------------------------------
/// Each round:
///  1. openRound()   — anyone opens a round; the CURRENT block's BTC/USD price
///                     is snapshotted from the Price oracle as the reference.
///  2. betUp/betDown — players stake QWD on the direction until closeBlock.
///  3. settle()      — callable only at least DRAW_DELAY blocks AFTER
///                     closeBlock: reads the Price oracle again to decide the
///                     winning side, and the RAND oracle to draw one bonus
///                     winner among the winning bettors. The pot is split
///                     pro-rata among winners; the bonus winner additionally
///                     receives the losing side's dust remainder.
///
/// The randomness is safe here because every bet was committed at or before
/// closeBlock, while the drawing randomness comes from a block at least
/// DRAW_DELAY later — unknowable at commitment time.
contract BtcUpDown {
    using QwidOracles for *;

    uint256 public constant MIN_BET = 1e8;      // 1 QWD (8 decimals)
    uint256 public constant DRAW_DELAY = 6;     // oracle update interval (~1 min)

    struct Round {
        uint256 openPrice;      // BTC/USD at open
        uint256 closeBlock;     // last block bets are accepted in
        uint256 upPot;
        uint256 downPot;
        address[] upBettors;
        address[] downBettors;
        mapping(address => uint256) upStake;
        mapping(address => uint256) downStake;
        bool settled;
        uint256 settlePrice;    // BTC/USD at settlement
        address bonusWinner;    // drawn with the RAND oracle
    }

    uint256 public roundCount;
    mapping(uint256 => Round) private rounds;
    // Winnings are pulled, not pushed: one failing transfer must not block
    // everyone else's payout.
    mapping(address => uint256) public payouts;

    event RoundOpened(uint256 indexed id, uint256 openPrice, uint256 closeBlock);
    event BetPlaced(uint256 indexed id, address indexed bettor, bool up, uint256 amount);
    event RoundSettled(uint256 indexed id, uint256 settlePrice, bool upWon, address bonusWinner);
    event PayoutClaimed(address indexed bettor, uint256 amount);

    /// @notice Open a new round accepting bets for `duration` blocks.
    function openRound(uint256 duration) external returns (uint256 id) {
        require(duration >= 1, "round must accept bets for at least one block");
        id = ++roundCount;
        Round storage r = rounds[id];
        r.openPrice = QwidOracles.priceBTCUSD();   // Price oracle read #1
        r.closeBlock = block.number + duration;
        emit RoundOpened(id, r.openPrice, r.closeBlock);
    }

    function betUp(uint256 id) external payable { _bet(id, true); }
    function betDown(uint256 id) external payable { _bet(id, false); }

    function _bet(uint256 id, bool up) internal {
        Round storage r = rounds[id];
        require(r.openPrice != 0, "no such round");
        require(block.number <= r.closeBlock, "betting closed");
        require(msg.value >= MIN_BET, "bet below minimum");
        if (up) {
            if (r.upStake[msg.sender] == 0) r.upBettors.push(msg.sender);
            r.upStake[msg.sender] += msg.value;
            r.upPot += msg.value;
        } else {
            if (r.downStake[msg.sender] == 0) r.downBettors.push(msg.sender);
            r.downStake[msg.sender] += msg.value;
            r.downPot += msg.value;
        }
        emit BetPlaced(id, msg.sender, up, msg.value);
    }

    /// @notice Settle a round. Only callable DRAW_DELAY blocks after close, so
    /// the randomness used for the bonus draw did not exist when bets closed.
    function settle(uint256 id) external {
        Round storage r = rounds[id];
        require(r.openPrice != 0, "no such round");
        require(!r.settled, "already settled");
        require(block.number >= r.closeBlock + DRAW_DELAY, "too early to settle");
        r.settled = true;

        r.settlePrice = QwidOracles.priceBTCUSD(); // Price oracle read #2

        // Price unchanged: nobody won — refund both sides in full.
        if (r.settlePrice == r.openPrice) {
            _refundAll(r);
            emit RoundSettled(id, r.settlePrice, false, address(0));
            return;
        }

        bool upWon = r.settlePrice > r.openPrice;
        address[] storage winners = upWon ? r.upBettors : r.downBettors;
        uint256 winPot = upWon ? r.upPot : r.downPot;
        uint256 losePot = upWon ? r.downPot : r.upPot;

        // Nobody on the winning side: refund the losing side (their opponents
        // never existed), burn nothing.
        if (winners.length == 0) {
            _refundAll(r);
            emit RoundSettled(id, r.settlePrice, upWon, address(0));
            return;
        }

        // Winners get their stake back plus a pro-rata share of the losing pot.
        uint256 distributed;
        for (uint256 i = 0; i < winners.length; i++) {
            address w = winners[i];
            uint256 stake = upWon ? r.upStake[w] : r.downStake[w];
            uint256 share = (losePot * stake) / winPot;
            payouts[w] += stake + share;
            distributed += share;
        }

        // RAND oracle: draw ONE bonus winner among the winning bettors, who
        // also receives the integer-division dust left by the pro-rata split.
        // Safe: every bet above was committed at block <= closeBlock, while
        // this randomness comes from a block >= closeBlock + DRAW_DELAY.
        uint256 rand = QwidOracles.randomness();
        address bonus = winners[rand % winners.length];
        payouts[bonus] += losePot - distributed;
        r.bonusWinner = bonus;

        emit RoundSettled(id, r.settlePrice, upWon, bonus);
    }

    /// @notice Withdraw accumulated winnings/refunds.
    function claim() external {
        uint256 amount = payouts[msg.sender];
        require(amount > 0, "nothing to claim");
        payouts[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit PayoutClaimed(msg.sender, amount);
    }

    // --- views ------------------------------------------------------------

    function roundInfo(uint256 id)
        external
        view
        returns (uint256 openPrice, uint256 closeBlock, uint256 upPot, uint256 downPot, bool settled, uint256 settlePrice, address bonusWinner)
    {
        Round storage r = rounds[id];
        return (r.openPrice, r.closeBlock, r.upPot, r.downPot, r.settled, r.settlePrice, r.bonusWinner);
    }

    /// @notice Live oracle readings — handy for UIs via the view-call RPC.
    function currentOracles() external view returns (uint256 price, uint256 rand) {
        return (QwidOracles.priceBTCUSD(), QwidOracles.randomness());
    }

    function _refundAll(Round storage r) internal {
        for (uint256 i = 0; i < r.upBettors.length; i++) {
            payouts[r.upBettors[i]] += r.upStake[r.upBettors[i]];
        }
        for (uint256 i = 0; i < r.downBettors.length; i++) {
            payouts[r.downBettors[i]] += r.downStake[r.downBettors[i]];
        }
    }
}
