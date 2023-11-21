# l2check
This project contains the software implementation for my diploma thesis.
A the moment the implementation is a rough prototype where much improvement is needed.

The l2check framework does automatically check for problems within the Layer 2 Broadcast Domain of a network.
At the moment a computer with four network interfaces is needed.
The first three network interfaces need to be in the same Broadcast Domain.
The fourth should be in a different VLAN (for the VLAN Hopping attack).
To run the Test just execute the `main.py`.
The attacks that should be executed are defined within `config.yaml`. 

Each attack is implemented in a seperate file within the `attacks` folder.
The attack class must have the same name as the file and has to inherit from the `Attack` base class.
