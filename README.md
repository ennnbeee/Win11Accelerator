# 📲 Win11Accelerator

Win11Accelerator is a PowerShell based utility that allows for the tagging of Windows 10 devices with their Windows 11 Feature Update risk score, to allow for a controlled update to Windows 11.

## ⚠ Public Preview Notice

Win11Accelerator is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.4.0**
  - Support for Windows 11 26H2
- v0.3.5
  - Support for Windows 11 25H2
- v0.3.4
  - Updated filtering when getting Entra ID objects
- v0.3.3
  - Improved interface and error handling
- v0.3.2
  - Bug fixes for attribute assignment
- v0.3.1
  - Bug fixes and update to parameter configurations
- v0.3.0
  - Allows for automatic deployment of the selected Feature Update to the low risk group
- v0.2.4
  - Updated to support creation of Dynamic Groups
  - Included a whatIf mode
  - Improved performance of functions
  - Improved logic of attribute assignment
- v0.2.0
  - Allows creation of Dynamic Groups
- v0.1.0
  - Initial release

## 🔑 Permissions

The PowerShell script requires the below Graph API permissions, you can create an Entra ID App Registration with the following Graph API Application permissions:

- `Device.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `DeviceManagementConfiguration.ReadWrite.All`
- `User.ReadWrite.All`
- `DeviceManagementRBAC.Read.All`
- `Group.ReadWrite.All`

## ⏯ Usage

Download the `Win11Accelerator.ps1` script, and from the saved location in a standard or elevated PowerShell prompt run one of the following:

### 🧪 Testing

Run the script to assign **Windows 11 24H2** Feature Update risk states to **extensionAttribute 11** with warning prompts in **whatIf** mode where no changes are made:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 11 -whatIf $true
```

### ⚙ General Usage

Run the script to assign **Windows 11 24H2** Feature Update risk states to **extensionAttribute 10** with warning prompts:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 10
```

> [!TIP]
> For large environments the initial run of the script may be interrupted by the authentication token expiring, please run the script again in the event this happens.

### ⚙ Continued Usage

Following the initial run the script, you can suppress the warning prompts by running the script to assign **Windows 11 24H2** Feature Update risk states to **extensionAttribute 10** without warning prompts:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 10 -firstRun $false
```

### 🛍 Group Creation

If you want the script to create dynamic groups based on the extension attribute risk state, include the boolean parameter `createGroups`:

```PowerShell
.\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 10 -createGroups $true -prefix 'Win11Acc-'
```

This will allow for groups to be created with a prefix of **Win11Acc-**, only if a group with the same name does not already exist.

## 🎬 Demos

![W11Accelerator](img/w11a-demo.gif)

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/Win11Accelerator/issues) page
2. Open a new issue if needed

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
