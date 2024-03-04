# Yii Role-Based Access Control Change Log

## 2.0.0 under development

- Chg #161: Allow to reuse manager test code in related packages (@arogachev)
- New #161: Add `ManagerInterface` (@arogachev)
- Chg #161, #217: Raise PHP version to 8.1 (@arogachev)
- Bug #178: Exclude parent role from `Manager::getAllChildRoles()` (@arogachev)
- Enh #134: Improve handling and control of `Assignment::$createdAt` (@arogachev)
- Chg #134: Add `$createdAt` parameter to `ManagerInterface::assign()` (@arogachev)
- Chg #134: Replace all parameters with single `$assignment` parameter in `AssignmentsStorageInterface::add()` 
  (@arogachev)
- Enh #165, #206: Improve performance:
  - Optimize calls for getting child items within the loops.
  (@arogachev)
- Enh #165: Rename `getChildren` method to `getDirectAchildren()` in `ItemsStorageInterface` (@arogachev)
- Enh #165, #203, #206, #208, #237: Add methods to `ItemsStorageInterface`:
    - `roleExists()`;
    - `getRolesByNames()`;
    - `getPermissionsByNames()`;
    - `getAllChildren()`;
    - `getAllChildRoles()`;
    - `getAllChildPermissions()`;
    - `hasChild()`;
    - `hasDirectChild()`;
    - `getByNames()`;
    - `getHierarchy()`.
      (@arogachev)
- Enh #165, #203: Add methods to `AssignmentsStorageInterface`:
  - `getByItemNames()`;
  - `exists()`;
  - `userHasItem()`;
  - `filterUserItemNames()`.
    (@arogachev)
- Enh #165: Rename `DefaultRoleNotFoundException` to `DefaultRolesNotFoundException` and finalize it (@arogachev)
- Bug #172: Execute rule when checking permissions for guests (@arogachev)
- Chg #172: Make `$userId` parameter `nullable` in `RuleInterface::execute()` (@arogachev)
- Bug #175: Use rule factory for creating rule instances in `CompositeRule` (@arogachev)
- Enh #202, #203: Add methods to `ManagerInterface`:
  - `getRole()`;
  - `getPermission()`;
  - `hasChildren()`;
  - `getItemsByUserId()`.
    (@arogachev)
- Chg #202: Rename `$permissionName` parameter to `$name` in `ManagerInterface::removePermission()` method (@arogachev)
- Bug #203: Execute rules for parent items and for guests in `Manager::userHasPermission()` (@arogachev)
- Bug #203: Do not limit child items by only direct ones for guests in `Manager::userHasPermission()` (@arogachev)
- Bug #203: Fix `Manager::getRolesByUserId()` to include child roles (@arogachev)
- Chg #203: Verify that every passed role name is a string in `Manager::setDefaultRoleNames()` (@arogachev)
- Enh #203: Add methods to `Manager`:
  - `getGuestRoleName()`;
  - `getGuestRole()`.
  (@arogachev)
- Chg #203: Throw `RuntimeException` in the case with implicit guest and non-existing guest role in
  `Manager::userHasPermission()` (@arogachev)
- Enh #204: Add simple storages for items and assignments (@arogachev)
- Bug #221: Exclude items with base names when getting children (@arogachev)
- Bug #222: Adjust hierarchy when removing item (@arogachev)
- Bug #223: Handle empty assignments in `Manager::getPermissionsByUserId()` (@arogachev)
- Enh #227: Use snake case for item attribute names (ease migration from Yii 2) (@arogachev)
- New #230: Add `Assignment::getAttributes()` method (@arogachev)
- Enh #245: Handle same names during renaming item in `AssignmentsStorage` (@arogachev)
- Enh #252: Return `$this` instead of throwing "already assigned" exception in `Manager::assign()` (@arogachev)
- Enh #248: Add `SimpleRuleFactory` (@arogachev)
- Enh #251: Allow checking for user's roles in `ManagerInterface::userHasPermission()` (@arogachev)
- Chg #259: Rename `$ruleContext` argument to `$context` in `RuleInterface::execute()` (@arogachev)
- Bug #260: Fix `Manager::userHasPermission()` to return `true` for the case when a user have access via at least one 
  hierarchy branch (@arogachev) 

## 1.0.2 April 20, 2023

- Technical release, no code changes.

## 1.0.1 April 20, 2023

- Enh #121: Throw friendly exception when getting non-existing default roles (@DplusG)

## 1.0.0 April 08, 2022

- Initial release.
