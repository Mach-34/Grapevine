# Grapevine

## Run Basic Test Steps
1. Clone the repo
`git clone https://github.com/mach-34/grapevine && cd grapevine`

2. Start the database with docker (in new terminal) 
`cd crates/grapevine_server/ && docker compose up`

3. Start the server (in new terminal)
`cd crates/grapevine_server/ && cargo run`

4. Install the grapevine cli (in original terminal window)
`cargo install --path crates/grapevine_cli`

5. Run the basic test demonstrating MVP
`./scripts/moving_degree_test.sh`

See [the test file](./scripts/moving_degree_test.sh) for insights on driving the CLI manually.
Docs will come once the codebase is not as messy and edge cases are handled