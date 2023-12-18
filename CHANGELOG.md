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
- Chg #172: Make `$userId` parameter `nullable` in `RuleInterface::execute()` (@arogachev)
- Bug #175: Use rule factory for creating rule instances in `CompositeRule` (@arogachev)
- Enh #202: Add `getRole()`, `getPermission()` and `hasChildren()` methods to `ManagerInterface` (@arogachev)
- Chg #202: Rename `$permissionName` parameter to `$name` in `ManagerInterface::removePermission()` method (@arogachev)
- Enh #203: Add `getByNames()` and `getAccessTree` methods to `ItemsStorageInterface` (@arogachev)
- Enh #203: Add `filterUserItemNames()` method to `AssignmentsStorageInterface` (@arogachev)
- Enh #203: Add `getItemsByUserId()` method to `ManagerInterface` (@arogachev)
- Bug #203: Remove duplicated code for checking permission in `Manager::userHasPermission()` (@arogachev)
- Bug #203: Execute rules for parent items and for guests in `Manager::userHasPermission()` (@arogachev)
- Bug #203: Do not limit child items by only direct ones for guests in `Manager::userHasPermission()` (@arogachev)
- Bug #203: Fix `Manager::getRolesByUserId()` to include child roles (@arogachev)
- Chg #203: Verify that every passed role name is a string in `Manager::setDefaultRoleNames()` (@arogachev)
- Enh #203: Add `getGuestRoleName()` and `getGuestRole()` methods to `Manager` (@arogachev)
- Chg #203: Throw `RuntimeException` in the case with implicit guest and non-existing guest role in
  `Manager::userHasPermission()` (@arogachev)
- Enh #206: Optimize calls for getting child items within the loops (@arogachev)
- Chg #206: Rename `$name` argument to `$names` and allow array type for it in `getAllChildren()`, `getAllChildRoles()`,
  `getAllChildPermissions()` methods of `ItemsStorageInterface` (@arogachev)
- Enh #204: Add simple storages for items and assignments (@arogachev)
- Chg #217: Raise PHP version to 8.1 (@arogachev)
- Bug #221: Exclude items with base names when getting children (@arogachev)
- Bug #?: Adjust hierarchy when removing item (@arogachev) 

## 1.0.2 April 20, 2023

- Technical release, no code changes.

## 1.0.1 April 20, 2023

- Enh #121: Throw friendly exception when getting non-existing default roles (@DplusG)

## 1.0.0 April 08, 2022

- Initial release.
