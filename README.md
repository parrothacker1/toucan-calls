# toucan-calls
The toucan carries our bits

## What is this ?
It is a SCTP based VoIP server made with go.

## Features
* It uses ECIES for establishing a secure connection and AES-GCM for encrypting the packets
* It uses Opus encoding on the audio
* It has Reed-Solomon inbuilt into it for correction of packets during recieving.

## What all i failed to implement
* Personalised streaming option for every client in a room. So that when mixing, they won't hear their voice in the incoming audio.
* Mixing itself. Running out of time to complete this project. Maybe after some while i will come back and fix these.

