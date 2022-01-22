# AGCOD Client

Steps to reproduce our issue:
1. Clone this repository with `git clone git@github.com:thealphaversion/AGCOD-Client.git`.
2. `cd` to this repository on your local machine.
3. Create an environment with `python3 -m venv env`.
4. Activate the environment with `source env/bin/activate`.
5. Replace placeholder `key` and `secret` with your own.
6. Run the client with `python3 client.py`.

The client will print all parts of the request when making the request.

If you only wish to prepare the request and print the request that is being sent,
but not send it, comment line 311 in client.py and uncomment line 314.

If you want to use a fixed date time string for debugging, comment line 58 in client.py,
and uncomment line 59 in client.py.