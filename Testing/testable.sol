pragma solidity ^0.4.23;

contract Testable {
    address public human;
    uint private counter;

    constructor() {
        human = tx.origin;
    }

    event CallmeLog();
    function callme(uint times) public {
        counter++;
        if (times > 1) {
            callme(--times);
        } else {
            emit CallmeLog();
        }
    }
}