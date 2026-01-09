Python Port Scanner

This is a small Python script that scans an IP address or website
to see which TCP ports are open.

Modules used:
- socket – used to connect to ports
- sys – used to exit the program
- re – used to check if the input is valid
- datetime – used to show scan time
- concurrent.futures – used to scan ports faster using threads

About:
The script connects to each port and checks if it is open.
It uses multiple threads so the scan does not take too long.
This was made for learning and basic security testing.
