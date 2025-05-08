# Codebeamer Connector

## Installation

1. Run the application once as administrator to install the Windows service:
   - Right-click on `app.exe` and select "Run as administrator"
   - The service will be automatically installed and started

2. The service will start automatically when Windows boots up.

## Managing the Service

### Starting the Service
- The service starts automatically at system boot
- It can be manually started through the Services console (services.msc)
- You can also run: `app.exe` as administrator to start it

### Stopping the Service
- Option 1: Services Console
  - Open services.msc
  - Find "Codebeamer Connector"
  - Right-click and select "Stop"

- Option 2: Command Line
  - Run Command Prompt as administrator
  - Execute: `sc stop CodebeamerConnector`

- Option 3: Using the Application
  - Run: `app.exe --stop` as administrator

### Uninstalling the Service
- Open an admin command prompt (right-click cmd.exe and select "Run as administrator")
- Run: `sc delete CodebeamerConnector`

## Troubleshooting

If the service doesn't start:

1. Check the service status:
   - Press Win+R, type `services.msc` and press Enter
   - Find "Codebeamer Connector" in the list

2. Look for error logs:
   - Check the `service-error.log` file in the same directory as app.exe
   - Look for shutdown information in `service-shutdown.log`

## Configuration

Settings are stored in the `settings.json` file in the same directory as app.exe.

## Service Status Files

The service creates status files in its directory:
- `service-error.log`: Contains any errors encountered
- `service-shutdown.log`: Records shutdown events