# 📲 Win11Accelerator

Win11Accelerator is a PowerShell based utility that allows for the tagging of Windows 10 devices with their Windows 11 Feature Update risk score, to allow for a controlled update to Windows 11.

## ⚠ Public Preview Notice

Win11Accelerator is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create and an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.2.1**
  - Function improvements and bug fixes
- v0.2
  - Updated to support creation of Dynamic Groups
  - Included a whatIf mode
- v0.1
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

Run the script to assign **Windows 11 23H2** Feature Update risk states to **extensionAttribute 10** with warning prompts:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 23H2 -target device -extensionAttribute 10
```

Run the script to assign **Windows 11 24H2** Feature Update risk states to **extensionAttribute 8** in **whatIf** mode where changes will be simulated:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 23H2 -target device -extensionAttribute 8 -whatIf
```

Run the script to assign **Windows 11 24H2** Feature Update risk states to **extensionAttribute 10** without warning prompts:

```powershell
.\Win11Accelerator.ps1 -featureUpdateBuild 23H2 -target device -extensionAttribute 10 -firstRun $false
```

### 🛍 Group Creation

If you want the script to create dynamic groups based on the extension attribute risk state, include the switch parameter `createGroups`:

```PowerShell
.\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 10 -createGroups
```

This will allow for groups to be created with a prefix of **Win11Acc-**, only if a group with the same name does not already exist.

> [!NOTE]
> If you want to change the Group name prefix update the `$groupPrefix` variable.

## 🎬 Demos

![W11Accelerator](img/w11a-demo.gif)

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/EPManager/issues) page
2. Open a new issue if needed

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
