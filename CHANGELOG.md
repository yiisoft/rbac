# Yii Role-Based Access Control Change Log

## 2.0.0 under development

- Chg #161: Allow to reuse manager test code in related packages (@arogachev)
- New #161: Add `ManagerInterface` (@arogachev)
- Chg #161: Raise PHP version to 8.0 (@arogachev)
- Enh #165: Improve perfomance (@arogachev)
- Bug #178: Exclude parent role from `Manager::getAllChildRoles()` (@arogachev)
- Enh #134: Improve handling and control of `Assignment::$createdAt` (@arogachev)
- Chg #134: Add `$createdAt` parameter to `ManagerInterface::assign()` (@arogachev)
- Chg #134: Replace parameters with `$assignment` parameter in `AssignmentsStorageInterface::add()` (@arogachev)

## 1.0.2 April 20, 2023

- Technical release, no code changes.

## 1.0.1 April 20, 2023

- Enh #121: Throw friendly exception when getting non-existing default roles (@DplusG)

## 1.0.0 April 08, 2022

- Initial release.
