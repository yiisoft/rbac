# Yii Role-Based Access Control Change Log

## 2.0.0 under development

- Chg #161: Allow to reuse manager test code in related packages (@arogachev)
- New #161: Add `ManagerInterface` (@arogachev)
- Chg #161: Raise PHP version to 8.0 (@arogachev)
- Bug #178: Exclude parent role from `Manager::getAllChildRoles()` (@arogachev)
- Enh #134: Improve handling and control of `Assignment::$createdAt` (@arogachev)
- Chg #134: Add `$createdAt` parameter to `ManagerInterface::assign()` (@arogachev)
- Chg #134: Replace parameters with `$assignment` parameter in `AssignmentsStorageInterface::add()` (@arogachev)
- Enh #165: Improve performance (@arogachev)
- Enh #165: Rename `getChildren` method to `getDirectAchildren()` in `ItemsStorageInterface` (@arogachev)
- Enh #165: Add methods to `ItemsStorageInterface`:
    - `roleExists()`;
    - `getRolesByNames()`;
    - `getPermissionsByNames()`;
    - `getAllChildren()`;
    - `getAllChildRoles()`;
    - `getAllChildPermissions()`;
    - `hasChild()`;
    - `hasDirectChild()`.
      (@arogachev)
- Enh #165: Add methods to `AssignmentsStorageInterface`:
  - `getByItemNames()`;
  - `exists()`;
  - `userHasItem()`.
    (@arogachev)
- Enh #165: Rename `DefaultRoleNotFoundException` to `DefaultRolesNotFoundException` and finalize it (@arogachev)
- Bug #172: Execute rule when checking permissions for guests (@arogachev)
- Bug #172: Make `$userId` parameter `nullable` in `RuleInterface::execute()` (@arogachev) 

## 1.0.2 April 20, 2023

- Technical release, no code changes.

## 1.0.1 April 20, 2023

- Enh #121: Throw friendly exception when getting non-existing default roles (@DplusG)

## 1.0.0 April 08, 2022

- Initial release.
