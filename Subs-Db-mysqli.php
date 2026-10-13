<?php

/**
 * Simple Machines Forum (SMF)
 *
 * @package SMF
 * @author Simple Machines http://www.simplemachines.org
 * @copyright 2011 Simple Machines
 * @license http://www.simplemachines.org/about/smf/license.php BSD
 *
 * @version 2.0
 */

if (!defined('SMF'))
	die('Hacking attempt...');

function smf_db_initiate($db_server,$db_name, $db_user,$db_passwd, $db_prefix,$db_options = array())
{
	global $smcFunc, $mysqli_set_mode,$db_port;

	if (!isset($smcFunc['db_fetch_assoc']) || $smcFunc['db_fetch_assoc'] != 'mysqli_fetch_assoc')$smcFunc += array(
			'db_query' => 'smf_db_query',
			'db_quote' => 'smf_db_quote',
			'db_fetch_assoc' => 'mysqli_fetch_assoc',
			'db_fetch_row' => 'mysqli_fetch_row',
			'db_free_result' => 'mysqli_free_result',
			'db_insert' => 'smf_db_insert',
			'db_insert_id' => 'smf_db_insert_id',
			'db_num_rows' => 'mysqli_num_rows',
			'db_data_seek' => 'mysqli_data_seek',
			'db_num_fields' => 'mysqli_num_fields',
			'db_escape_string' => 'addslashes',
			'db_unescape_string' => 'stripslashes',
			'db_server_info' => 'smf_db_get_server_info',
			'db_affected_rows' => 'smf_db_affected_rows',
			'db_transaction' => 'smf_db_transaction',
			'db_error' => 'mysqli_error',
			'db_select_db' => 'smf_db_select',
			'db_title' => 'mysqli',
			'db_sybase' => false,
			'db_case_sensitive' => false,
			'db_escape_wildcard_string' => 'smf_db_escape_wildcard_string',
		);

	$port = !empty($db_port) ? (int)$db_port : (int) ini_get("mysqli.default_port");
	if (empty($port))$port = 3306;

	if (strpos($db_server, ':') !== false)
	{
		list($host_only, $port_only) = explode(':',$db_server, 2);
		$db_server =$host_only;
		if (!empty($port_only))
		{
			$port = (int)$port_only;
			$db_port =$port;
		}
	}

	$connection = @mysqli_connect($db_server,$db_user, $db_passwd, '',$port);

	if (!$connection)
	{
		if (!empty($db_options['non_fatal']))
			return null;
		else
			db_fatal_error();
	}

	if (empty($db_options['dont_select_db']) && !@mysqli_select_db($connection, $db_name) && empty($db_options['non_fatal']))
		db_fatal_error();

	if (isset($mysqli_set_mode) && $mysqli_set_mode === true)$smcFunc['db_query']('', 'SET sql_mode = "", AUTOCOMMIT = 1',
			array(),
			false
		);

	return $connection;
}

function db_extend($type = 'extra')
{
	global $sourcedir,$db_type;

	require_once($sourcedir . '/Db' . strtoupper($type[0]) . substr($type, 1) . '-' . $db_type . '.php');$initFunc = 'db_' . $type . '_init';$initFunc();
}

function db_fix_prefix(&$db_prefix,$db_name)
{
	$db_prefix = is_numeric(substr($db_prefix, 0, 1)) ? $db_name . '.' .$db_prefix : '`' . $db_name . '`.' . $db_prefix;
}

function smf_db_connect($override_user = null,$override_passwd = null)
{
	global $db_server, $db_user,$db_passwd, $db_name,$db_port;

	$user =$override_user !== null ? $override_user :$db_user;
	$passwd =$override_passwd !== null ? $override_passwd :$db_passwd;

	$server =$db_server;
	$port = !empty($db_port) ? (int)$db_port : (int) ini_get("mysqli.default_port");
	if (empty($port))$port = 3306;

	if (strpos($server, ':') !== false)
	{
		list($host_only, $port_only) = explode(':',$server, 2);
		$server =$host_only;
		if (!empty($port_only))
			$port = (int)$port_only;
	}

	return @mysqli_connect($server, $user,$passwd, $db_name,$port);
}

function smf_db_select($database,$connection)
{
	if (!is_object($connection))$connection = smf_db_connect();

	return mysqli_select_db($connection,$database);
}

function smf_db_get_server_info()
{
	global $db_connection;

	$connection = is_object($db_connection) ?$db_connection : smf_db_connect();
	return $connection ? mysqli_get_server_info($connection) : '';
}

function smf_db_replacement__callback($matches)
{
	global $db_callback, $user_info,$db_prefix;

	list ($values, $connection) =$db_callback;

	if (!is_object($connection))$connection = smf_db_connect();

	if ($matches[1] === 'db_prefix')
		return $db_prefix;

	if ($matches[1] === 'query_see_board')
		return $user_info['query_see_board'];

	if ($matches[1] === 'query_wanna_see_board')
		return $user_info['query_wanna_see_board'];

	if (!isset($matches[2]))
		smf_db_error_backtrace('Invalid value inserted or no type specified.', '', E_USER_ERROR, __FILE__, __LINE__);

	if (!isset($values[$matches[2]]))
		smf_db_error_backtrace('The database value you are trying to insert does not exist: ' . htmlspecialchars($matches[2]), '', E_USER_ERROR, __FILE__, __LINE__);

	$replacement = $values[$matches[2]];

	switch ($matches[1])
	{
		case 'int':
			if (!is_numeric($replacement) || (string) $replacement !== (string) (int)$replacement)
				smf_db_error_backtrace('Wrong value type sent to the database. Integer expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);
			return (string) (int) $replacement;
		break;

		case 'string':
		case 'text':
			return sprintf("'%1$s'", mysqli_real_escape_string($connection,$replacement));
		break;

		case 'array_int':
			if (is_array($replacement))
			{
				if (empty($replacement))
					smf_db_error_backtrace('Database error, given array of integer values is empty. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);

				foreach ($replacement as $key =>$value)
				{
					if (!is_numeric($value) || (string) $value !== (string) (int)$value)
						smf_db_error_backtrace('Wrong value type sent to the database. Array of integers expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);

					$replacement[$key] = (string) (int)$value;
				}

				return implode(', ', $replacement);
			}
			else
				smf_db_error_backtrace('Wrong value type sent to the database. Array of integers expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);

		break;

		case 'array_string':
			if (is_array($replacement))
			{
				if (empty($replacement))
					smf_db_error_backtrace('Database error, given array of string values is empty. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);

				foreach ($replacement as$key => $value)$replacement[$key] = sprintf("'\%1$s'", mysqli_real_escape_string($connection,$value));

				return implode(', ', $replacement);
			}
			else
				smf_db_error_backtrace('Wrong value type sent to the database. Array of strings expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);
		break;

		case 'date':
			if (preg_match('#^(\d{4})-([0-1]?\d)-([0-3]?\d)$#', $replacement,$date_matches) === 1)
				return sprintf("'%04d-%02d-%02d'", $date_matches[1], $date_matches[2],$date_matches[3]);
			else
				smf_db_error_backtrace('Wrong value type sent to the database. Date expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);
		break;

		case 'float':
			if (!is_numeric($replacement))
				smf_db_error_backtrace('Wrong value type sent to the database. Floating point number expected. (' . $matches[2] . ')', '', E_USER_ERROR, __FILE__, __LINE__);
			return (string) (float) $replacement;
		break;

		case 'identifier':
			return '`' . strtr($replacement, array('`' => '', '.' => '')) . '`';
		break;

		case 'raw':
			return $replacement;
		break;

		default:
			smf_db_error_backtrace('Undefined type used in the database query. (' . $matches[1] . ':' . $matches[2] . ')', '', false, __FILE__, __LINE__);
		break;
	}
}

function smf_db_quote($db_string, $db_values, $connection = null)
{
	global $db_callback, $db_connection;

	if (strpos($db_string, '{') !== false)
	{
		$db_callback = array($db_values, $connection == null ? $db_connection : $connection);
		$db_string = preg_replace_callback('#{([a-z_]+)(?::([a-zA-Z0-9_-]+))?}#', 'smf_db_replacement__callback', $db_string);
		$db_callback = array();
	}

	return $db_string;
}

function smf_db_query($identifier, $db_string, $db_values = array(), $connection = null)
{
	global $db_cache, $db_count, $db_connection, $db_show_debug, $time_start;
	global $db_unbuffered, $db_callback, $modSettings;

	static $allowed_comments_from = array(
		'#\s+#s',
		'#/\*!40001 SQL_NO_CACHE \*/#',
		'#/\*!40000 USE INDEX \([A-Za-z\_]+?\) \*/#',
		'#/\*!40100 ON DUPLICATE KEY UPDATE id_msg = \d+ \*/#',
	);
	static $allowed_comments_to = array(
		' ',
		'',
		'',
		'',
	);

	$connection = $connection == null ? $db_connection : $connection;
	if (!is_object($connection))
		$connection = smf_db_connect();

	$db_count = !isset($db_count) ? 1 : $db_count + 1;

	if (empty($modSettings['disableQueryCheck']) && strpos($db_string, "'") !== false && empty($db_values['security_override']))
		smf_db_error_backtrace('Hacking attempt...', 'Illegal character used in query...', true, __FILE__, __LINE__);

	if (strpos($db_string, 'GROUP BY') !== false && strpos($db_string, 'ORDER BY') === false && strpos($db_string, 'INSERT INTO') === false)
	{
		if ($pos = strpos($db_string, 'LIMIT '))
			$db_string = substr($db_string, 0, $pos) . "\t\t\tORDER BY null\n" . substr($db_string, $pos, strlen($db_string));
		else
			$db_string .= "\n\t\t\tORDER BY null";
	}

	if (empty($db_values['security_override']) && (!empty($db_values) || strpos($db_string, '{db_prefix}') !== false))
	{
		$db_callback = array($db_values, $connection);
		$db_string = preg_replace_callback('#{([a-z_]+)(?::([a-zA-Z0-9_-]+))?}#', 'smf_db_replacement__callback', $db_string);
		$db_callback = array();
	}

	if (isset($db_show_debug) && $db_show_debug === true)
	{
		list ($file, $line) = smf_db_error_backtrace('', '', 'return', __FILE__, __LINE__);

		if (!isset($db_cache))
			$db_cache = array();

		if (!empty($_SESSION['debug_redirect']))
		{
			$db_cache = array_merge($_SESSION['debug_redirect'], $db_cache);
			$db_count = count($db_cache) + 1;
			$_SESSION['debug_redirect'] = array();
		}

		$st = microtime();
		$db_cache[$db_count]['q'] = $db_count < 50 ? $db_string : '...';
		$db_cache[$db_count]['f'] = $file;
		$db_cache[$db_count]['l'] = $line;
		$db_cache[$db_count]['s'] = array_sum(explode(' ', $st)) - array_sum(explode(' ', $time_start));
	}

	if (empty($modSettings['disableQueryCheck']))
	{
		$clean = '';
		$old_pos = 0;
		$pos = -1;
		while (true)
		{
			$pos = strpos($db_string, "'", $pos + 1);
			if ($pos === false)
				break;
			$clean .= substr($db_string, $old_pos, $pos - $old_pos);

			while (true)
			{
				$pos1 = strpos($db_string, "'", $pos + 1);
				$pos2 = strpos($db_string, "\\", $pos + 1);
				if ($pos1 === false)
					break;
				elseif ($pos2 == false || $pos2 > $pos1)
				{
					$pos = $pos1;
					break;
				}

				$pos = $pos2 + 1;
			}
			$clean .= ' %s ';

			$old_pos = $pos + 1;
		}
		$clean .= substr($db_string, $old_pos);
		$clean = trim(strtolower(preg_replace($allowed_comments_from, $allowed_comments_to, $clean)));

		if (strpos($clean, 'union') !== false && preg_match('#(^|[^a-z])union($|[^[a-z])#s', $clean) != 0)
			$fail = true;
		elseif (strpos($clean, '/*') > 2 || strpos($clean, '--') !== false || strpos($clean, ';') !== false)
			$fail = true;
		elseif (strpos($clean, 'sleep') !== false && preg_match('#(^|[^a-z])sleep($|[^[_a-z])#s', $clean) != 0)
			$fail = true;
		elseif (strpos($clean, 'benchmark') !== false && preg_match('#(^|[^a-z])benchmark($|[^[a-z])#s', $clean) != 0)
			$fail = true;
		elseif (preg_match('#\([^)]*?select#s', $clean) != 0)
			$fail = true;

		if (!empty($fail) && function_exists('log_error'))
			smf_db_error_backtrace('Hacking attempt...', "Hacking attempt...\n" . $db_string, E_USER_ERROR, __FILE__, __LINE__);
	}

	if (empty($db_unbuffered))
		$ret = @mysqli_query($connection, $db_string);
	else
		$ret = @mysqli_query($connection, $db_string);

	if ($ret === false && empty($db_values['db_error_skip']))
		$ret = smf_db_error($db_string, $connection);

	if (isset($db_show_debug) && $db_show_debug === true)
		$db_cache[$db_count]['t'] = array_sum(explode(' ', microtime())) - array_sum(explode(' ', $st));

	return $ret;
}

function smf_db_affected_rows($connection = null)
{
	global $db_connection;

	$connection = $connection == null ? $db_connection : $connection;
	if (!is_object($connection))
		$connection = smf_db_connect();

	return mysqli_affected_rows($connection);
}

function smf_db_insert_id($table, $field = null, $connection = null)
{
	global $db_connection, $db_prefix;

	$table = str_replace('{db_prefix}', $db_prefix, $table);

	$connection = $connection == null ? $db_connection : $connection;
	if (!is_object($connection))
		$connection = smf_db_connect();

	return mysqli_insert_id($connection);
}

function smf_db_transaction($type = 'commit', $connection = null)
{
	global $db_connection;

	$connection = $connection == null ? $db_connection : $connection;
	if (!is_object($connection))
		$connection = smf_db_connect();

	if ($type == 'begin')
		return @mysqli_query($connection, 'BEGIN');
	elseif ($type == 'rollback')
		return @mysqli_query($connection, 'ROLLBACK');
	elseif ($type == 'commit')
		return @mysqli_query($connection, 'COMMIT');

	return false;
}

function smf_db_error($db_string, $connection = null)
{
	global $txt, $context, $sourcedir, $webmaster_email, $modSettings;
	global $forum_version, $db_connection, $db_last_error, $db_persist;
	global $db_server, $db_user, $db_passwd, $db_name, $db_show_debug, $ssi_db_user, $ssi_db_passwd;
	global $smcFunc;

	list ($file, $line) = smf_db_error_backtrace('', '', 'return', __FILE__, __LINE__);

	$connection = $connection == null ? $db_connection : $connection;
	if (!is_object($connection))
		$connection = smf_db_connect();

	$query_error = mysqli_error($connection);
	$query_errno = mysqli_errno($connection);

	if ($query_errno != 1213 && $query_errno != 1205 && function_exists('log_error'))
		log_error($txt['database_error'] . ': ' . $query_error . (!empty($modSettings['enableErrorQueryLogging']) ? "\n\n" . $db_string : ''), 'database', $file, $line);

	if (function_exists('cache_get_data') && (!isset($modSettings['autoFixDatabase']) || $modSettings['autoFixDatabase'] == '1'))
	{
		$old_cache = @$modSettings['cache_enable'];
		$modSettings['cache_enable'] = '1';

		if (($temp = cache_get_data('db_last_error', 600)) !== null)
			$db_last_error = max(@$db_last_error, $temp);

		if (@$db_last_error < time() - 3600 * 24 * 3)
		{
			if ($query_errno == 1030 && strpos($query_error, ' 127 ') !== false)
			{
				//preg_match_all("#(?:[\\n\\r]|^)[^']+(?:FROM|JOIN|UPDATE|TABLE) ((?:[^\\n\\r(]+(?:, )?)*)#s", $db_string, $matches);
				//preg_match_all('~(?:[\n\r]|^)[^\']+?(?:FROM|JOIN|UPDATE|TABLE) ((?:[^\n\r(]+?(?:, )?)*)~s', $db_string, $matches);
				preg_match_all("#(?:[\n\r]|^)[^']+(?:FROM|JOIN|UPDATE|TABLE) ((?:[^\n\r(]+(?:, )?)*)#s", $db_string, $matches);

				$fix_tables = array();
				foreach ($matches[1] as $tables)
				{
					$tables = array_unique(explode(',', $tables));
					foreach ($tables as $table)
					{
						if (trim($table) != '')
							$fix_tables[] = '`' . strtr(trim($table), array('`' => '')) . '`';
					}
				}

				$fix_tables = array_unique($fix_tables);
			}
			elseif ($query_errno == 1016)
			{
				//if (preg_match("#'([^.]+)'#", $query_error, $match) != 0)$fix_tables = array('`' . $match[1] . '`');
				if (preg_match("#'([^.]+)'#", $query_error, $match) != 0)
			}
			elseif ($query_errno == 1034 \vert{}\vert{}$query_errno == 1035)
			{
				//preg_match("#'([^']+)'#", $query_error, $match);$fix_tables = array('`' . $match[1] . '`');
				preg_match("#'([^']+)'#", $query_error, $match);
			}
		}

		if (!empty($fix_tables))
		{
			require_once($sourcedir . '/Subs-Admin.php');
			require_once($sourcedir . '/Subs-Post.php');

			cache_put_data('db_last_error', time(), 600);
			if (($temp = cache_get_data('db_last_error', 600)) === null)
				updateSettingsFile(array('db_last_error' => time()));

			foreach ($fix_tables as$table)
				$smcFunc['db_query']('', 'REPAIR TABLE ' .$table, false, false);

			sendmail($webmaster_email, $txt['database_error'],$txt['tried_to_repair']);

			$modSettings['cache_enable'] =$old_cache;

			$ret = $smcFunc['db_query']('',$db_string, false, false);
			if ($ret !== false)
				return $ret;
		}
		else
			$modSettings['cache_enable'] =$old_cache;

		if (in_array($query_errno, array(1205, 1213, 2006, 2013)))
		{
			if (in_array($query_errno, array(2006, 2013)) && $db_connection ==$connection)
			{
				if (SMF == 'SSI' && !empty($ssi_db_user) && !empty($ssi_db_passwd))
				{
					$db_connection = smf_db_connect($ssi_db_user,$ssi_db_passwd);
				}
				if (!$db_connection)
				{
					$db_connection = smf_db_connect();
				}

				if (!$db_connection \vert{}\vert{} !@mysqli_select_db($db_connection, $db_name))$db_connection = false;
			}

			if ($db_connection)
			{
				for ($n = 0; $n < 4; $n++)
				{
					$ret = $smcFunc['db_query']('',$db_string, false, false);

					$new_errno = mysqli_errno($db_connection);
					if ($ret !== false \vert{}\vert{} in_array($new_errno, array(1205, 1213)))
						break;
				}

				if ($ret !== false)
					return $ret;
			}
		}
		elseif ($query_errno == 1030 && (strpos($query_error, ' -1 ') !== false || strpos($query_error, ' 28 ') !== false \vert{}\vert{} strpos($query_error, ' 12 ') !== false))
		{
			if (!isset($txt))$query_error .= ' - check database storage space.';
			else
			{
				if (!isset($txt['mysqli_error_space']))
					loadLanguage('Errors');

				$query_error .= !isset($txt['mysqli_error_space']) ? ' - check database storage space.' :$txt['mysqli_error_space'];
			}
		}
	}

	if (empty($context) \vert{}\vert{} empty($txt))
		die($query_error);

	$context['error_title'] =$txt['database_error'];
	if (allowedTo('admin_forum'))
		$context['error_message'] = nl2br($query_error) . '<br />' . $txt['file'] . ': ' .$file . '<br />' . $txt['line'] . ': ' .$line;
	else
		$context['error_message'] =$txt['try_again'];

	if (allowedTo('admin_forum') && !empty($forum_version) && $forum_version != 'SMF ' . @$modSettings['smfVersion'] && strpos($forum_version, 'Demo') === false && strpos($forum_version, 'CVS') === false)
		$context['error_message'] .= '<br /><br />' . sprintf($txt['database_error_versions'], $forum_version,$modSettings['smfVersion']);

	if (allowedTo('admin_forum') && isset($db_show_debug) &&$db_show_debug === true)
	{
		$context['error_message'] .= '<br /><br />' . nl2br($db_string);
	}

	fatal_error($context['error_message'], false);
}

function smf_db_insert($method = 'replace', $table,$columns, $data,$keys, $disable_trans = false,$connection = null)
{
	global $smcFunc, $db_connection,$db_prefix;

	$connection =$connection === null ? $db_connection :$connection;
	if (!is_object($connection))$connection = smf_db_connect();

	if (empty($data))
		return;

	$table = str_replace('{db_prefix}', $db_prefix,$table);

	if (!is_array($data[array_rand($data)]))
		$data = array($data);

	$insertData = '(';
	foreach ($columns as $columnName =>$type)
	{
		if (strpos($type, 'string-') !== false)
			$insertData .= sprintf('SUBSTRING({string:\%1$s}, 1, ' . substr($type, 7) . '), ',$columnName);
		else
			$insertData .= sprintf('{%1$s:\%2$s}, ', $type,$columnName);
	}
	$insertData = substr($insertData, 0, -2) . ')';

	$indexed_columns = array_keys($columns);

	$insertRows = array();
	foreach ($data as $dataRow)$insertRows[] = smf_db_quote($insertData, array_combine($indexed_columns, $dataRow),$connection);

	$queryTitle = $method == 'replace' ? 'REPLACE' : ($method == 'ignore' ? 'INSERT IGNORE' : 'INSERT');

	$smcFunc['db_query']('', $queryTitle . ' INTO ' .$table . '(`' . implode('`, `', $indexed_columns) . '`) VALUES ' . implode(', ', $insertRows),
		array(
			'security_override' => true,
			'db_error_skip' => $table ===$db_prefix . 'log_errors',
		),
		$connection
	);
}

function smf_db_error_backtrace($error_message, $log_message = '',$error_type = false, $file = null,$line = null)
{
	if (empty($log_message))
		$log_message =$error_message;

	if (function_exists('debug_backtrace'))
	{
		foreach (debug_backtrace() as $step)
		{
			if (strpos($step['function'], 'query') === false && !in_array(substr($step['function'], 0, 7), array('smf_db_', 'preg_re', 'db_erro', 'call_us')) && substr($step['function'], 0, 2) != '__')
			{
				$log_message .= '<br />Function: ' .$step['function'];
				break;
			}

			if (isset($step['line']))
			{
				$file =$step['file'];
				$line =$step['line'];
			}
		}
	}

	if ($error_type == 'return')
		return array($file,$line);

	if (function_exists('log_error'))
		log_error($log_message, 'critical', $file,$line);

	if (function_exists('fatal_error'))
	{
		fatal_error($error_message, false);

		exit;
	}
	elseif ($error_type)
		trigger_error($error_message . ($line !== null ? '<em>(' . basename($file) . '-' . $line . ')</em>' : ''),$error_type);
	else
		trigger_error($error_message . ($line !== null ? '<em>(' . basename($file) . '-' .$line . ')</em>' : ''));
}

function smf_db_escape_wildcard_string($string,$translate_human_wildcards = false)
{
	$replacements = array(
		'%' => '\%',
		'_' => '\_',
		'\\' => '\\\\',
	);

	if ($translate_human_wildcards)$replacements += array(
			'*' => '%',
		);

	return strtr($string,$replacements);
}
?>
