<?php
/*
Plugin Name: Multiple Secondary Passwords with Logging & Filters
Description: Unlock a password-protected post using the main WP password or multiple secondary passwords, rely on WordPress's default 'wp-postpass_' cookie, and log each access attempt with date/time/IP/geolocation.
Version: 1
Author: Adam Chiaravalle @ ACWebDev, LLC.
*/

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Add admin menu to manage secondary passwords + logs.
 */
function epwc_add_admin_menu() {
	add_menu_page(
		'AC - Multi Passwords & Logs',
		'AC - Multi Passwords',
		'manage_options',
		'epwc-secondary-passwords',
		'epwc_render_admin_page',
		'dashicons-lock',
		60
	);
}
add_action('admin_menu', 'epwc_add_admin_menu');

/**
 * Renders the Admin Page (top table for passwords, bottom table for logs).
 */
function epwc_render_admin_page() {
	if (!current_user_can('manage_options')) {
		return;
	}

	// 1) SAVE POSTED PASSWORDS ---------------------------------------------
	if (isset($_POST['epwc_nonce']) && wp_verify_nonce($_POST['epwc_nonce'], 'epwc_save_passwords')) {
		if (isset($_POST['epwc_secondary_passwords']) && is_array($_POST['epwc_secondary_passwords'])) {
			foreach ($_POST['epwc_secondary_passwords'] as $post_id => $password_array) {
				$cleaned = array();
				foreach ($password_array as $pwd) {
					$pwd = trim(sanitize_text_field($pwd));
					if (!empty($pwd)) {
						$cleaned[] = $pwd;
					}
				}
				update_post_meta($post_id, '_epwc_secondary_passwords', $cleaned);
			}
		}
		echo '<div class="updated notice"><p>Secondary passwords updated successfully!</p></div>';
	}

	// 2) SHOW PASSWORD-PROTECTED POSTS WITH URL + SECONDARY PASSWORDS ------
	$protected_posts = new WP_Query(array(
		'post_type'      => 'any',
		'posts_per_page' => -1,
		'has_password'   => true
	));
	?>
	<div class="wrap">
		<h1>Multiple Secondary Passwords & Access Logs</h1>
		<p>Manage multiple secondary passwords. The access logs table is below with filtering options.</p>

		<form method="post">
			<?php wp_nonce_field('epwc_save_passwords', 'epwc_nonce'); ?>
			<table class="widefat fixed" style="margin-bottom: 30px;">
				<thead>
					<tr>
						<th>Post / URL</th>
						<th>Main Password (read-only)</th>
						<th>Secondary Passwords</th>
					</tr>
				</thead>
				<tbody>
				<?php if ($protected_posts->have_posts()) : ?>
					<?php while ($protected_posts->have_posts()) : $protected_posts->the_post(); ?>
						<?php
							$post_id             = get_the_ID();
							$main_password       = get_post_field('post_password', $post_id);
							$secondary_passwords = get_post_meta($post_id, '_epwc_secondary_passwords', true);
							if (!is_array($secondary_passwords)) {
								$secondary_passwords = array();
							}
							$post_url = get_permalink($post_id);
						?>
						<tr>
							<td>
								<a href="<?php echo esc_url($post_url); ?>" target="_blank">
									<?php echo esc_html(get_the_title()); ?>
								</a>
								<div style="font-size: 0.9em; color: #777;">
									<?php echo esc_url($post_url); ?>
								</div>
							</td>
							<td>
								<input type="text"
									   readonly
									   value="<?php echo esc_attr($main_password); ?>" />
							</td>
							<td>
								<div class="epwc-password-list" data-postid="<?php echo esc_attr($post_id); ?>">
									<?php foreach ($secondary_passwords as $index => $pwd_value) : ?>
										<p>
											<input type="text"
												   name="epwc_secondary_passwords[<?php echo esc_attr($post_id); ?>][]"
												   value="<?php echo esc_attr($pwd_value); ?>" />
											<button type="button" class="button epwc-remove-password">Remove</button>
										</p>
									<?php endforeach; ?>
									<!-- Empty template for new password fields -->
									<p class="epwc-password-template" style="display:none;">
										<input type="text"
											   name="epwc_secondary_passwords[<?php echo esc_attr($post_id); ?>][]"
											   value="" />
										<button type="button" class="button epwc-remove-password">Remove</button>
									</p>
								</div>
								<button type="button" class="button epwc-add-password" data-postid="<?php echo esc_attr($post_id); ?>">
									Add Password
								</button>
							</td>
						</tr>
					<?php endwhile; ?>
					<?php wp_reset_postdata(); ?>
				<?php else : ?>
					<tr><td colspan="3">No password-protected posts found.</td></tr>
				<?php endif; ?>
				</tbody>
			</table>
			<?php submit_button('Save Secondary Passwords'); ?>
		</form>

		<script>
		document.addEventListener('DOMContentLoaded', function() {
			// Handle Add
			document.querySelectorAll('.epwc-add-password').forEach(function(btn){
				btn.addEventListener('click', function(){
					var postid = this.getAttribute('data-postid');
					var container = document.querySelector('.epwc-password-list[data-postid="'+postid+'"]');
					var template = container.querySelector('.epwc-password-template');
					if(template) {
						var newRow = template.cloneNode(true);
						newRow.style.display = 'block';
						newRow.classList.remove('epwc-password-template');
						container.appendChild(newRow);
					}
				});
			});

			// Handle Remove
			document.querySelectorAll('.epwc-password-list').forEach(function(list){
				list.addEventListener('click', function(e){
					if(e.target && e.target.classList.contains('epwc-remove-password')) {
						e.preventDefault();
						e.target.parentNode.remove();
					}
				});
			});
		});
		console.log("Verbose dev info: Admin top table loaded for multiple secondary passwords.");
		</script>

		<?php
		// 3) LOGS TABLE WITH FILTERS ---------------------------------------------

		// Gather all logs from all protected posts:
		$all_logs = array();
		$all_passwords = array(); // Collect unique passwords
		$all_post_choices = array(); // Collect unique post choices

		$logs_posts = get_posts(array(
			'post_type'   => 'any',
			'numberposts' => -1,
			'has_password'=> true
		));

		if ($logs_posts) {
			foreach ($logs_posts as $lp) {
				$post_logs = get_post_meta($lp->ID, '_epwc_access_logs', true);
				if (is_array($post_logs)) {
					foreach ($post_logs as $log_entry) {
						$entry = array(
							'post_id'   => $lp->ID,
							'post_title'=> get_the_title($lp->ID),
							'post_url'  => get_permalink($lp->ID),
							'datetime'  => isset($log_entry['datetime']) ? $log_entry['datetime'] : '',
							'ip'        => isset($log_entry['ip']) ? $log_entry['ip'] : '',
							'location'  => isset($log_entry['location']) ? $log_entry['location'] : '',
							'password'  => isset($log_entry['password']) ? $log_entry['password'] : ''
						);
						$all_logs[] = $entry;
						if (!empty($entry['password'])) {
							$all_passwords[] = $entry['password'];
						}
					}
				}
				$all_post_choices[] = array(
					'ID'    => $lp->ID,
					'title' => get_the_title($lp->ID)
				);
			}
		}

		// Remove duplicates from the arrays:
		$all_passwords = array_unique($all_passwords);
		// Sort them alphabetically
		asort($all_passwords);

		// Sort post choices by title
		usort($all_post_choices, function($a, $b){
			return strcasecmp($a['title'], $b['title']);
		});

		// Process the filtering:
		$filter_password = isset($_GET['epwc_filter_password']) ? sanitize_text_field($_GET['epwc_filter_password']) : '';
		$filter_postid   = isset($_GET['epwc_filter_postid']) ? intval($_GET['epwc_filter_postid']) : 0;
		$sort_date       = isset($_GET['epwc_sort_date']) ? sanitize_text_field($_GET['epwc_sort_date']) : 'asc';

		// Filter logs by password
		if (!empty($filter_password)) {
			$all_logs = array_filter($all_logs, function($log) use ($filter_password){
				return ($log['password'] === $filter_password);
			});
		}
		// Filter logs by post
		if ($filter_postid > 0) {
			$all_logs = array_filter($all_logs, function($log) use ($filter_postid){
				return ($log['post_id'] == $filter_postid);
			});
		}
		// Sort logs by date
		usort($all_logs, function($a, $b) use ($sort_date){
			$t1 = strtotime($a['datetime']);
			$t2 = strtotime($b['datetime']);
			if ($t1 == $t2) {
				return 0;
			}
			if ($sort_date === 'asc') {
				return ($t1 < $t2) ? -1 : 1;
			} else {
				return ($t1 > $t2) ? -1 : 1;
			}
		});
		?>
		
		<h2 style="margin-top: 40px;">Access Logs</h2>
		<p>Filter or sort the logs below:</p>
		<form method="get">
			<!-- Preserve the page in the query -->
			<input type="hidden" name="page" value="epwc-secondary-passwords" />
			<input type="hidden" name="sort" value="logs" />

			<table style="margin-bottom:1em;">
				<tr>
					<td>Password Used:</td>
					<td>
						<select name="epwc_filter_password">
							<option value="">All</option>
							<?php foreach ($all_passwords as $pwd): ?>
								<option value="<?php echo esc_attr($pwd); ?>" <?php selected($filter_password, $pwd); ?>>
									<?php echo esc_html($pwd); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
					<td style="padding-left:20px;">Page:</td>
					<td>
						<select name="epwc_filter_postid">
							<option value="0">All</option>
							<?php foreach ($all_post_choices as $choice): ?>
								<option value="<?php echo esc_attr($choice['ID']); ?>"
									<?php selected($filter_postid, $choice['ID']); ?>>
									<?php echo esc_html($choice['title']); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
					<td style="padding-left:20px;">Sort by Date:</td>
					<td>
						<select name="epwc_sort_date">
							<option value="asc" <?php selected($sort_date, 'asc'); ?>>Ascending</option>
							<option value="desc" <?php selected($sort_date, 'desc'); ?>>Descending</option>
						</select>
					</td>
					<td style="padding-left:20px;">
						<input type="submit" class="button" value="Apply Filters" />
					</td>
				</tr>
			</table>
		</form>

		<?php if (!empty($all_logs)): ?>
			<table class="widefat fixed">
				<thead>
					<tr>
						<th>Date/Time</th>
						<th>IP</th>
						<th>Geolocation</th>
						<th>Password Used</th>
						<th>Post Title</th>
						<th>URL</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ($all_logs as $log): ?>
					<tr>
						<td><?php echo esc_html($log['datetime']); ?></td>
						<td><?php echo esc_html($log['ip']); ?></td>
						<td><?php echo esc_html($log['location']); ?></td>
						<td><?php echo esc_html($log['password']); ?></td>
						<td><?php echo esc_html($log['post_title']); ?></td>
						<td>
							<a href="<?php echo esc_url($log['post_url']); ?>" target="_blank">
								<?php echo esc_html($log['post_url']); ?>
							</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php else: ?>
			<p><em>No logs found based on current filters.</em></p>
		<?php endif; ?>
	</div>
	<?php
}

/**
 * Hook into 'login_form_postpass' to rewrite the typed password if it matches a secondary one.
 * Then log usage: date/time/IP/geolocation.
 */
add_action('login_form_postpass', 'epwc_rewrite_if_secondary', 1);
function epwc_rewrite_if_secondary() {
	if (isset($_POST['post_password']) && !empty($_POST['post_password'])) {
		$typed_password = sanitize_text_field($_POST['post_password']);

		// Try to figure out the post ID
		$redirect_url = !empty($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : wp_get_referer();
		if (!empty($redirect_url)) {
			$post_id = url_to_postid($redirect_url);
		} else {
			$post_id = 0;
		}
		if (!$post_id && wp_get_referer()) {
			$post_id = url_to_postid(wp_get_referer());
		}

		if ($post_id) {
			$main_password       = get_post_field('post_password', $post_id);
			$secondary_passwords = get_post_meta($post_id, '_epwc_secondary_passwords', true);
			if (!is_array($secondary_passwords)) {
				$secondary_passwords = array();
			}

			if (in_array($typed_password, $secondary_passwords, true)) {
				$_POST['post_password'] = $main_password;
				epwc_log_secondary_password_use($post_id, $typed_password);

				add_action('login_head', function() use ($post_id) {
					?>
					<script>
					console.log("Verbose dev info: User typed a valid secondary password for post ID <?php echo esc_js($post_id); ?>. Rewriting to main password for the WP cookie.");
					</script>
					<?php
				});
			}
		}
	}
}

/**
 * Logs each successful secondary password usage.
 */
function epwc_log_secondary_password_use($post_id, $used_password) {
	$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
	$location = epwc_get_geolocation($ip);

	$access_logs = get_post_meta($post_id, '_epwc_access_logs', true);
	if (!is_array($access_logs)) {
		$access_logs = array();
	}
	$access_logs[] = array(
		'datetime' => current_time('mysql'),
		'ip'       => $ip,
		'location' => $location,
		'password' => $used_password
	);
	update_post_meta($post_id, '_epwc_access_logs', $access_logs);
}

/**
 * Retrieves a basic geolocation string using ip-api.com (public API).
 * This is a simplistic approach. In production, consider error handling or a more robust service.
 */
function epwc_get_geolocation($ip) {
	$url      = 'http://ip-api.com/json/' . $ip;
	$response = wp_remote_get($url);
	if (is_wp_error($response)) {
		return 'Location unavailable';
	}
	$body = wp_remote_retrieve_body($response);
	$data = json_decode($body, true);
	if (isset($data['status']) && $data['status'] === 'success') {
		$country = isset($data['country']) ? $data['country'] : '';
		$region  = isset($data['regionName']) ? $data['regionName'] : '';
		$city    = isset($data['city']) ? $data['city'] : '';
		return $city . ', ' . $region . ', ' . $country;
	}
	return 'Location unavailable';
}

/**
 * Debugging in the footer on the front-end.
 */
function epwc_debug_footer() {
	?>
	<script>
	console.log("Verbose dev info: If typed password matched a secondary, we rewrote it and logged the event. Separate logs table with filters is now available in admin!");
	</script>
	<?php
}
add_action('wp_footer', 'epwc_debug_footer');