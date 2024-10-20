# SSH-Guard

**SSH-Guard** is a secure and flexible server application that provides an abstraction layer for executing pre-defined SSH commands on remote servers. This application makes use of a RESTful API to expose SSH commands, allowing you to execute them via POST requests without the need to directly connect to the target systems.

### Key Features
- **Pre-defined SSH Commands**: Define and map multiple SSH commands to secure and limit the actions that can be executed.
- **Token-based Authentication**: Use API tokens with customizable permissions to control access to specific servers and commands.
- **IP Blocker**: Prevent brute force attacks by blocking IPs that provide incorrect API keys after a certain number of attempts.
- **JSON Configuration**: Configure commands, SSH hosts, and API tokens via a JSON configuration file.
- **Class-based Architecture**: Leverages a clean, class-based approach to managing SSH hosts, commands, API tokens, and IP blocking.

## Docker Installation

### Step-by-step Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/SURFER00/ssh-guard.git
    cd ssh-guard
    ```

2. **Create a configuration file**:

    ```bash
    cp config.sample.json config.json
    ```

3. **Run**:
   
   ```bash
   docker compose up -d --build
   ```
