// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

/// ---------------------------------------------------------------------------
/// OracleDollar (QUSD) — a QWID token that uses BOTH consensus oracles.
/// ---------------------------------------------------------------------------
/// * It is a QWID token: name/symbol/decimals/balanceOf/transfer(address,int64)
///   are exactly the five selectors blocks.IsTokenToRegister looks for, so the
///   node registers it at deployment and it can be traded on the protocol DEX.
///   Balances are int64, as the DEX reads them (not ERC-20 uint256).
/// * PRICE ORACLE (0x…0100): 1 QUSD is minted for 1 USD worth of QWD and can
///   be redeemed for 1 USD worth of QWD, at the price sealed in the block of
///   the transaction. On testnet the oracle carries BTC/USD as a stand-in.
/// * RAND ORACLE (0x…0101): a periodic prize draw among QUSD holders who
///   entered it, using the commit-first pattern — entries close at a block
///   height and the draw runs at least DRAW_DELAY blocks later, so the
///   randomness did not exist when anyone entered.
///
/// Units: QWD has 8 decimals (msg.value is in base units, 1 QWD = 1e8); the
/// price oracle is USD per QWD * 1e8; QUSD has 8 decimals too, so
///     QUSD base units = msg.value * price / 1e8.
///
/// Compile (as the web UI does):
///     solc --evm-version paris --optimize --bin --abi smartContracts/oracleToken.sol
/// Deploy: a transaction with Recipient empty and OptData = the creation
/// bytecode. Call: Recipient = token address, OptData = ABI-encoded call,
/// Amount = QWD sent along (msg.value) for mint().
contract OracleDollar {
    // --- QWID token interface (the five registration selectors) ---------
    string public constant name = "Oracle Dollar";
    string public constant symbol = "QUSD";
    uint8 public constant decimals = 8;
    mapping(address => int64) private balances;
    int64 public totalSupply;

    // --- oracles -------------------------------------------------------
    address constant PRICE_ORACLE = address(0x100);
    address constant RAND_ORACLE = address(0x101);
    uint256 constant ONE = 1e8;          // 8 decimals for QWD, USD price and QUSD

    // --- prize draw ----------------------------------------------------
    uint256 public constant DRAW_DELAY = 6;   // blocks between close and draw
    address public owner;
    int64 public prizePool;                    // QUSD set aside for prizes
    uint256 public drawCloseBlock;             // entries accepted up to here
    address[] private entrants;
    mapping(address => uint256) private enteredRound;
    uint256 public round = 1;

    event Sent(address from, address to, int64 amount);
    event Minted(address indexed to, uint256 qwdPaid, int64 qusd, uint256 price);
    event Redeemed(address indexed from, int64 qusd, uint256 qwdPaid, uint256 price);
    event DrawOpened(uint256 indexed round, uint256 closeBlock, int64 prize);
    event DrawWon(uint256 indexed round, address winner, int64 prize, uint256 rand);

    constructor() {
        owner = msg.sender;
    }

    // ===================== token =======================================

    function balanceOf(address who) public view returns (int64) {
        return balances[who];
    }

    function transfer(address to, int64 amount) public {
        require(amount > 0, "amount must be positive");
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Sent(msg.sender, to, amount);
    }

    // ===================== price oracle: mint / redeem ==================

    /// @notice Current USD price of 1 QWD (* 1e8), as sealed in this block.
    function price() public view returns (uint256 p) {
        (bool ok, bytes memory out) = PRICE_ORACLE.staticcall("");
        require(ok && out.length == 32, "price oracle unavailable");
        p = abi.decode(out, (uint256));
        require(p > 0, "price oracle not established yet");
    }

    /// @notice Mint QUSD for the QWD sent along: 1 QUSD per 1 USD.
    /// @param minQusd least QUSD to accept (slippage guard: the oracle price
    ///        of the including block may differ from the one you saw).
    function mint(int64 minQusd) external payable returns (int64 qusd) {
        uint256 p = price();
        qusd = _toInt64((msg.value * p) / ONE);
        require(qusd > 0, "send more QWD");
        require(qusd >= minQusd, "price moved: less QUSD than minQusd");
        balances[msg.sender] += qusd;
        totalSupply += qusd;
        emit Minted(msg.sender, msg.value, qusd, p);
    }

    /// @notice Burn QUSD and receive 1 USD worth of QWD per QUSD.
    /// @param minQwd least QWD (base units) to accept (slippage guard).
    function redeem(int64 qusd, uint256 minQwd) external returns (uint256 qwd) {
        require(qusd > 0 && qusd <= balances[msg.sender], "insufficient balance");
        uint256 p = price();
        qwd = (uint256(int256(qusd)) * ONE) / p;
        require(qwd >= minQwd, "price moved: less QWD than minQwd");
        require(qwd <= address(this).balance, "reserve too small");
        balances[msg.sender] -= qusd;
        totalSupply -= qusd;
        (bool ok, ) = msg.sender.call{value: qwd}("");
        require(ok, "QWD transfer failed");
        emit Redeemed(msg.sender, qusd, qwd, p);
    }

    // ===================== RAND oracle: prize draw ======================

    /// @notice Consensus randomness sealed in this block (RANDAO).
    function randomness() public view returns (uint256 r) {
        (bool ok, bytes memory out) = RAND_ORACLE.staticcall("");
        require(ok && out.length == 32, "rand oracle unavailable");
        r = abi.decode(out, (uint256));
    }

    /// @notice Owner opens a draw: moves `prize` of its own QUSD into the
    ///         pool and accepts entries for `duration` blocks.
    function openDraw(int64 prize, uint256 duration) external {
        require(msg.sender == owner, "only owner");
        require(drawCloseBlock == 0, "a draw is already open");
        require(prize > 0 && prize <= balances[msg.sender], "fund the prize from your balance");
        require(duration >= 1, "duration must be at least one block");
        balances[msg.sender] -= prize;
        prizePool = prize;
        drawCloseBlock = block.number + duration;
        emit DrawOpened(round, drawCloseBlock, prize);
    }

    /// @notice Enter the open draw. Only QUSD holders may enter, once each.
    function enter() external {
        require(drawCloseBlock != 0 && block.number <= drawCloseBlock, "no draw open for entries");
        require(balances[msg.sender] > 0, "hold QUSD to enter");
        require(enteredRound[msg.sender] != round, "already entered");
        enteredRound[msg.sender] = round;
        entrants.push(msg.sender);
    }

    /// @notice Anyone can run the draw, but only DRAW_DELAY blocks after the
    ///         entries closed: the RAND of this block was unknowable when the
    ///         last entry was made. Mixing in the round number and the close
    ///         height gives each round its own draw from the same RAND.
    function draw() external returns (address winner) {
        require(drawCloseBlock != 0, "no draw open");
        require(block.number >= drawCloseBlock + DRAW_DELAY, "too early to draw");
        int64 prize = prizePool;
        uint256 rand = randomness();
        if (entrants.length == 0) {
            balances[owner] += prize;   // nobody entered: the prize goes back
        } else {
            uint256 pick = uint256(keccak256(abi.encode(rand, round, drawCloseBlock)));
            winner = entrants[pick % entrants.length];
            balances[winner] += prize;
        }
        emit DrawWon(round, winner, prize, rand);
        prizePool = 0;
        drawCloseBlock = 0;
        delete entrants;
        round++;
    }

    function entrantCount() external view returns (uint256) {
        return entrants.length;
    }

    // ===================== helpers =====================================

    function _toInt64(uint256 x) private pure returns (int64) {
        require(x <= uint256(int256(type(int64).max)), "amount too large");
        return int64(int256(x));
    }
}
