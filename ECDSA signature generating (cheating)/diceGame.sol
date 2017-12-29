pragma solidity 0.4.19;

contract Ownable {
    address public owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner); _;
    }
}

contract DiceGame is Ownable {

    uint public testResult;

    enum GameState {
        InProgress,
        PlayerWon,
        PlayerLose
    }

    struct Game {
        address player;
        uint bet;
        bytes32 seed;
        GameState state;
        uint result;
    }

    event LogNewGame(bytes32 seed);

    mapping(bytes32 => Game) public listGames;

    // starts a new game
    function roll(bytes32 seed) public payable {
        require(listGames[seed].player == 0x0);

        listGames[seed] = Game({
            player: msg.sender,
            bet: msg.value,
            seed: seed,
            state: GameState.InProgress,
            result: 13
        });

        LogNewGame(seed);
    }

    event LogPlayerLose(bytes32 seed);
    event LogPlayerWon(bytes32 seed);

    function confirm(bytes32 seed, uint8 _v, bytes32 _r, bytes32 _s) public onlyOwner {

        if (ecrecover(seed, _v, _r, _s) == owner) {
            Game game = listGames[seed];
            game.result = uint256(_s) % 12;

            if (game.result <= 3 ) {
                game.state = GameState.PlayerLose;
                LogPlayerLose(seed);
            } else {
                game.state = GameState.PlayerWon;
                game.player.transfer(game.bet * 2);
                LogPlayerWon(seed);
            }
        }
    }

    function () payable {

    }
}