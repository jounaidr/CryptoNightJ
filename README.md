# CryptoNightJ
An unoptimised Java native implementation of the CryptoNight proof of work algorithm, see [CryptoNightJNI](https://github.com/jounaidr/CryptoNightJNI) for an optimal solution.

The algorithms implementation can be found in: [Cryptonight.java](https://github.com/jounaidr/CryptoNightJ/blob/main/src/main/java/Cryptonight.java) with various other hashing packages used.

### Algorithm Overview
The CryptoNight algorithm consists of three sections: scratchpad initialisation, memory-hard loop and results calculation. The following three diagrams (based on the Cryptonote Standard 2013) provide an overview on how the algorithm functions. See the [Monero docs](https://monerodocs.org/proof-of-work/cryptonight/) for more info.

*scratchpad initialisation*

*memory-hard loop*

*results calculation*

### Dependencies
The project structure and dependencies can be seen in the following diagram:
![CryptoNightJ_expanded_dependancy_diagram](https://github.com/jounaidr/CryptoNightJ/blob/main/docs/resources/CryptoNightJ_expanded_dependancy_diagram.png)

### TODOs
- Optimisation throughout (see code)
- Refactor Cryptonight.java to implement hashing digest interface as to stay consistent with other Java hashing algorithms
