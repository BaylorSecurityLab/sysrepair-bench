#Requires -RunAsAdministrator
<#
.SYNOPSIS
Creates the three lab virtual switches. Idempotent.

.DESCRIPTION
SRB-Lab    Internal, 10.20.30.0/24 -- the AD segment, no host route out.
SRB-Build  External -- image bake only. NOT NAT: Hyper-V supports one NAT
           prefix per host and WSL2 already owns it, so a NAT switch here
           would break WSL networking.
SRB-Kernel Internal, 10.20.40.0/24 -- kernel-vm and hivestorm-14.

The host gets an address on each Internal segment because every readiness
probe runs from the host. Without it the probes cannot connect at all.

ORDERING: this MUST run before Install-Lab. AutomatedLab's
New-LWHypervNetworkSwitch checks Get-VMSwitch by name; if the switch already
exists it warns "no changes will be made to configuration" and skips host-vNIC
IP assignment. Running AutomatedLab first and this second fails the other way:
if the switch is absent but 10.20.30.1 is already bound, AL errors.
#>

function New-LabSwitches {
    [CmdletBinding()]
    param(
        # Mandatory by design: on a laptop the only physical adapter is often
        # Wi-Fi, and an External switch over a wireless NIC works only via
        # ARP-proxy bridging and is fragile. Make the operator choose.
        [Parameter(Mandatory)] [string] $ExternalAdapterName
    )

    $internal = @(
        @{ Name = 'SRB-Lab';    HostIP = '10.20.30.1'; Prefix = 24 },
        @{ Name = 'SRB-Kernel'; HostIP = '10.20.40.1'; Prefix = 24 }
    )

    foreach ($s in $internal) {
        if (-not (Get-VMSwitch -Name $s.Name -ErrorAction SilentlyContinue)) {
            New-VMSwitch -Name $s.Name -SwitchType Internal | Out-Null
            Write-Host "[switch] created $($s.Name) (Internal)"
        }

        $alias = "vEthernet ($($s.Name))"

        $existing = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 `
                        -ErrorAction SilentlyContinue |
                    Where-Object IPAddress -eq $s.HostIP

        if (-not $existing) {
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $s.HostIP `
                -PrefixLength $s.Prefix -ErrorAction Stop | Out-Null
            Write-Host "[switch] $($s.Name): host address $($s.HostIP)/$($s.Prefix)"
        }

        # Windows defaults an unidentified vNIC to Public, which firewalls the
        # host-side listeners the readiness probes depend on.
        # NOTE: deliberately NOT named $profile -- that is an automatic
        # variable ($PROFILE) and assigning to it clobbers the user's profile
        # path for the rest of the session.
        $netProfile = Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction SilentlyContinue
        if ($netProfile -and $netProfile.NetworkCategory -ne 'Private') {
            Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private
            Write-Host "[switch] $($s.Name): reclassified $($netProfile.NetworkCategory) -> Private"
        }
    }

    if (-not (Get-VMSwitch -Name 'SRB-Build' -ErrorAction SilentlyContinue)) {
        $adapter = Get-NetAdapter -Name $ExternalAdapterName -ErrorAction SilentlyContinue
        if (-not $adapter) {
            throw "New-LabSwitches: adapter '$ExternalAdapterName' not found. Available: $((Get-NetAdapter -Physical | Select-Object -ExpandProperty Name) -join ', ')"
        }
        New-VMSwitch -Name 'SRB-Build' -NetAdapterName $ExternalAdapterName `
            -AllowManagementOS $true | Out-Null
        Write-Host "[switch] created SRB-Build (External via $ExternalAdapterName)"
    }
}

function Get-LabSwitchHealth {
    <#
    .SYNOPSIS
    Reports switch type, host IP and NAT collision status.
    .OUTPUTS
    [pscustomobject] Name, Type, HostIP, Category, Healthy
    #>
    [CmdletBinding()] param()

    foreach ($n in 'SRB-Lab', 'SRB-Build', 'SRB-Kernel') {
        $sw    = Get-VMSwitch -Name $n -ErrorAction SilentlyContinue
        $alias = "vEthernet ($n)"
        $ip    = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 `
                     -ErrorAction SilentlyContinue | Select-Object -First 1
        $prof  = Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction SilentlyContinue

        [pscustomobject]@{
            Name     = $n
            Type     = $sw.SwitchType
            HostIP   = $ip.IPAddress
            Category = $prof.NetworkCategory
            Healthy  = [bool]$sw
        }
    }
}

function Test-NoLabNatCollision {
    <#
    .SYNOPSIS
    Asserts no Hyper-V NAT claims the lab prefixes.
    .DESCRIPTION
    VMSwitchType has no 'NAT' member -- a Hyper-V NAT is an Internal switch
    plus New-NetNat -- so testing SwitchType for NAT can never fail and proves
    nothing. Test the actual NAT table instead. Hyper-V supports one NAT prefix
    per host and WSL2 normally owns it.
    #>
    [CmdletBinding()] param()

    $collisions = Get-NetNat -ErrorAction SilentlyContinue |
        Where-Object { $_.InternalIPInterfaceAddressPrefix -like '10.20.*' }

    if ($collisions) {
        throw "Test-NoLabNatCollision: a NAT claims a lab prefix: $($collisions.InternalIPInterfaceAddressPrefix -join ', '). This will fight WSL2 for the single per-host NAT prefix."
    }

    Write-Host '[switch] no NAT collision on the lab prefixes'
    return $true
}
