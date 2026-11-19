# eq3-custom-fw-py
Python client for eQ-3 custom firmware (eQ-3 is a smart thermostat)

There is a [custom firmware](https://github.com/dbuezas/eq3-custom-fw) for [eqiva smart thermostats](https://www.eq-3.de/produkte/eqiva/detail/bluetooth-smart-heizkoerperthermostat.html) but only browser client is provided.

Given that the communication protocol is [very well documented](https://github.com/dbuezas/eq3-custom-fw/blob/main/PROTOCOL.md), I shamelessly vibe-slopped a python client for integration into my home automation setup. I didn't read the code, I didn't test all the features. It does what I want and it works on my machine™ (which runs linux but windows might work as well maybe).

I thought since I already used fresh water and polluted the world for this with CO2 and noise, I might as well publish it so other people can try if it works for them or use it as a starting point for slopping on top of it.

I recommend using the [original app](https://github.com/dbuezas/eq3-custom-fw) for testing and setting keys and everything and then playing with this python client.

For encrypted communication, create a file named `key.txt` and store the 32 character key in it. It must be the same key for all your thermostats.

`eq3.py` can be used both as a module and as a CLI app.

# Examples

```bash
# Discover thermostats
./eq3.py scan

# Listen to broadcasts
./eq3.py broadcast --duration 60

# Read version and serial
./eq3.py --address AA:BB:CC:DD:EE:FF version

# Read status
./eq3.py --address AA:BB:CC:DD:EE:FF status

# Set temperature
./eq3.py --address AA:BB:CC:DD:EE:FF set-temp 20.0

# Lock/unlock
./eq3.py --address AA:BB:CC:DD:EE:FF lock true
./eq3.py --address AA:BB:CC:DD:EE:FF lock false

# Window open/closed
./eq3.py --address AA:BB:CC:DD:EE:FF window true
./eq3.py --address AA:BB:CC:DD:EE:FF window false

# Read settings
./eq3.py --address AA:BB:CC:DD:EE:FF settings

# Read weekly schedule
./eq3.py --address AA:BB:CC:DD:EE:FF schedule-get

# Read one day (Saturday=0, Sunday=1, ...)
./eq3.py --address AA:BB:CC:DD:EE:FF schedule-get --day 0

# Write schedule (seven [temperature, end_minutes] pairs)
./eq3.py --address AA:BB:CC:DD:EE:FF schedule-set 0 \
  '[[20,360],[21,600],[20,900],[18,1440],[18,1440],[18,1440],[18,1440]]'

# Encrypted, unpaired (default)
./eq3.py --channel encrypted --address AA:BB:CC:DD:EE:FF status

# Paired and unencrypted
./eq3.py --channel plain --pair --address AA:BB:CC:DD:EE:FF status
```