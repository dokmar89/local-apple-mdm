export const AccessRights = {
  InspectProfiles: 1 << 0, // ProfileList
  ManageProfiles: 1 << 1, // InstallProfile, RemoveProfile
  DeviceLock: 1 << 2, // DeviceLock, ClearPasscode
  EraseDevice: 1 << 3, // EraseDevice
  DeviceInformation: 1 << 4, // DeviceInformation: general queries
  NetworkInformation: 1 << 5, // DeviceInformation: network queries
  InspectProvisioning: 1 << 6, // ProvisioningProfileList
  ManageProvisioning: 1 << 7, // InstallProvisioningProfile, RemoveProvisioningProfile
  InspectApplications: 1 << 8, // InstalledApplicationList
  Restrictions: 1 << 9, // Restrictions
  Security: 1 << 10, // SecurityInfo
  Settings: 1 << 11, // Settings
  ManageApplications: 1 << 12, // InstallApplication, RemoveApplication
} as const;
export const ALL_ACCESS_RIGHTS = Object.values(AccessRights).reduce(
  (mask, bit) => mask | bit,
  0,
);
