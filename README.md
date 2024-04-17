# Grapevine

## Installation Instructions
### Prerequisites
To use the Grapevine CLI, you must ensure you have:
1. [Rust installed](https://www.rust-lang.org/tools/install)
2. [Node version >=18.19.0](https://github.com/nvm-sh/nvm?tab=readme-ov-file#install--update-script)
### Installing the Grapevine CLI
Use the following steps to install the Grapevine CLI
```console
# Clone the git repository
git clone https://github.com/Mach-34/Grapevine.git && cd Grapevine

# Install the CLI globally on your machine
cargo install --path crates/grapevine_cli

# Check that the cli was installed correctly and is pointing at the remote server
grapevine health

# Output of `grapevine health` should be:
> SERVER URL IS: https://grapevine.mach34.space
> Health check passed
```

## Usage instructions
```console
   ______                           _           
  / ____/________ _____  ___ _   __(_)___  ___  
 / / __/ ___/ __ `/ __ \/ _ \ | / / / __ \/ _ \
/ /_/ / /  / /_/ / /_/ /  __/ |/ / / / / /  __/
\____/_/   \__,_/ .___/\___/|___/_/_/ /_/\___/  
               /_/

Usage: grapevine <COMMAND>

Commands:
  health        Test the connection to the Grapevine server
                    usage: `grapevine health`
  account       Commands for managing your Grapevine account
  relationship  Commands for managing relationships
  phrase        Commands for interacting with phrases and degree proofs
  help          Print this message or the help of the given subcommand(s)


```
### Account

#### Register
```console
# register a new account with the username "<username>"
grapevine account register <username>

# Example output
> Created Grapevine account at /home/user/.grapevine/grapevine.key
> Success: registered account for "<username>"
```
The first command you will run is . Assuming the username is not already taken, this will create a new account in the Grapevine service. Note that your username must be < 30 ASCII characters.

Your account is stored at `~/.grapevine/grapevine.key`. If you want to switch between accounts, you can move this file and register another account, and switch between account files stored at `~/.grapevine/grapevine.key`.

#### Info
```console
# get info about the account being used in the CLI
grapevine account info

# Example output
> Username: bob
> Public key: 0xa9d3158e650540b10f10abe7e8bc280740ed3b8a8035b596a3e391a1b9e5fbaa
> # 1st degree connections: 13
> # 2nd degree connections: 27
> # phrases created: 3
```
You can return basic information about your account. This includes public identity data like your username and public key as well as statistics about your account. Note that 1st degree connections denotes your direct relationships, and 2nd degree connections denotes all of the unique relationships of your 1st degree connections.

#### Export
```console
# Get the private & sensitive info used by this account
grapevine account export

# Example output
Sensitive account details for david:
Private Key: 0xb7607560c14ed6a564a69e3ffeef5f20fff07292427b4a054d2727e6860adcd8
Auth Secret: 0x95a1afe77f5ebdd1256f0168acd7357c55b05606a9a656029e3d5b18fb6a6806
```
You can export the secret information used by this account as well (though there is currently no way to import accounts into the Grapevine CLI).
 * Private key: Used to authorize CLI actions and derive encryption keys for sharing auth secrets and storing secret phrases
 * Auth secret: A random blinding factor used in phrase hashing to ensure each others can only build degrees from your proofs if you have an active relationship with them

### Relationship
#### Add
```console
# Send a connection request or approve it depending on whether they've already sent you a pending request
grapevine relationship add charlie

# Example output when david sends charlie a pending request
> Relationship from david to charlie pending!

# Example output when david activates a pending request from charlie
> Relationship from david to charlie pending!
```
In grapevine, there are "relationship" just like in any social media. You can send a request for someone to approve, and vice versa. This is done with the same command
