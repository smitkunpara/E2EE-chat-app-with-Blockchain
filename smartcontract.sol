// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserStorage {
    address public owner;

    struct UserData {
        string username;
        string user_password;
        string publickey;
        uint256 current_time;
    }

    mapping(string => UserData) public userDataByUsername;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this operation");
        _;
    }

    function setUser(
        string memory username,
        string memory user_password
    ) public onlyOwner {
        // Set default values for publickey and current_time
        userDataByUsername[username] = UserData(username, user_password, "", 0);
    }

    function updateUser(
        string memory username,
        string memory newPublickey,
        uint256 time
    ) public onlyOwner {
        UserData storage userData = userDataByUsername[username];

        // Check if the user exists
        require(bytes(userData.username).length > 0, "User does not exist");

        // Update user information
        userData.publickey = newPublickey;
        userData.current_time = time;
    }

    function getUserData(string memory username) public view returns (string memory, string memory, string memory, uint256) {
        UserData memory userData = userDataByUsername[username];
        return (userData.username, userData.user_password, userData.publickey, userData.current_time);
    }

    function changeOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
