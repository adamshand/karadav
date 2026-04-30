<?php

namespace KaraDAV;

require_once __DIR__ . '/_inc.php';

$user = $users->getById((int) $_GET['id']);

if (!$user) {
	throw new \LogicException('This user does not exist');
}

form_exec_if('save', function () use ($ldap, $user, $logged_user, $users) {
	if (!$ldap
		&& empty($_POST['is_admin'])
		&& $user->id == $logged_user->id) {
		throw new UserException(_('You cannot remove yourself from admins, ask another admin to do it for you.'));
	}

	$data = array_merge($_POST, ['is_admin' => !empty($_POST['is_admin'])]);

	if ($ldap) {
		unset($data['is_admin'], $data['password'], $data['login']);
	}

	$users->edit($user->id, $data);

	if (!empty($_POST['delete_avatar'])) {
		$users->deleteAvatar($user);
	}

	$users->saveAvatarFromUpload($user, $_FILES['avatar'] ?? null);

	if ($user->id === $logged_user->id) {
		$_SESSION['user'] = $users->getById($logged_user->id);
	}
}, 'users/');

$has_avatar = (bool) $users->avatarPath($user);

$tpl->assign(compact('user', 'has_avatar'));
$tpl->display('users/edit.tpl');
