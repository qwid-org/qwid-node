// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

contract Coin {

    // The keyword "public" makes variables
    // accessible from other contracts
    address public minter;
    mapping (address => int64) public balances;
    string public constant name = "WONABRU TOKEN";
    string public constant symbol = "WNB";
    uint8 public constant decimals = 2;

    function balanceOf(address tokenOwner) public view returns (int64) {
        return balances[tokenOwner];
    }

    // Events allow clients to react to specific
    // contract changes you declare
    event Sent(address from, address to, int64 amount);

    // Constructor code is only run when the contract
    // is created
    constructor() {
        minter = msg.sender;
    }

    // Sends an amount of newly created coins to an address
    // Can only be called by the contract creator
    function mint(address receiver, int64 amount) public {
        require(msg.sender == minter, "only minter can mint");
        require(amount > 0, "amount must be positive");
        balances[receiver] += amount;
    }

    // Sends an amount of existing coins
    // from any caller to an address
    function transfer(address receiver, int64 amount) public {
        // A negative amount would pass the balance check below and move
        // tokens from the receiver to the caller.
        require(amount > 0, "amount must be positive");
        require(amount <= balances[msg.sender], "insufficient balance");

        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Sent(msg.sender, receiver, amount);
    }
}