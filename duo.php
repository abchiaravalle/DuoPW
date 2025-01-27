<?php
/*
Plugin Name: Either Password with Standard WP Cookie
Plugin URI: https://example.com
Description: Unlock a password-protected post using either the main WP password or a secondary one, but still rely on WordPress's default 'wp-postpass_' cookie. We hook into 'login_form_postpass' to rewrite the posted password if it matches the secondary.
Version: 1.0
Author: Your Name
License: GPL2
*/

if (!defined('ABSPATH')) {
	exit; // Prevent direct access
}

/**
 * 1) Create an admin menu to manage secondary passwords per post.
 */
function epwc_add_admin_menu() {
	add_menu_page(
		'Either Password (WP Cookie)',
		'Either Password',
		'manage_options',
		'epwc-secondary-passwords',
		'epwc_render_admin_page',
		'dashicons-lock',
		60
	);
}
add_action('admin_menu', 'epwc_add_admin_menu');

/**
 * Render the Admin Page.
 */
function epwc_render_admin_page() {
	if (!current_user_can('manage_options')) {
		// If the user can't manage options, WordPress usually shows a 403 or redirects.
		// This might be why you're getting a 403 if you lack the correct capability.
		return;
	}

	// Save posted data
	if (isset($_POST['epwc_nonce']) && wp_verify_nonce($_POST['epwc_nonce'], 'epwc_save_passwords')) {
		if (isset($_POST['epwc_secondary_password']) && is_array($_POST['epwc_secondary_password'])) {
			foreach ($_POST['epwc_secondary_password'] as $post_id => $password_value) {
				update_post_meta($post_id, '_epwc_secondary_password', sanitize_text_field($password_value));
			}
		}
		echo '<div class="updated notice"><p>Secondary passwords updated successfully!</p></div>';
	}

	// Query all password-protected posts
	$protected_posts = new WP_Query(array(
		'post_type'      => 'any',
		'posts_per_page' => -1,
		'has_password'   => true
	));
	?>
	<div class="wrap">
		<h1>Either Password with Standard WP Cookie</h1>
		<p>If you see a 403, ensure you are logged in as an Administrator with the capability <code>manage_options</code> and that the plugin is active.</p>
		<form method="post">
			<?php wp_nonce_field('epwc_save_passwords', 'epwc_nonce'); ?>
			<table class="widefat fixed">
				<thead>
					<tr>
						<th>Post Title</th>
						<th>Main Password (read-only)</th>
						<th>Secondary Password</th>
					</tr>
				</thead>
				<tbody>
				<?php if ($protected_posts->have_posts()) : ?>
					<?php while ($protected_posts->have_posts()) : $protected_posts->the_post(); ?>
						<?php
							$post_id            = get_the_ID();
							$main_password      = get_post_field('post_password', $post_id);
							$secondary_password = get_post_meta($post_id, '_epwc_secondary_password', true);
						?>
						<tr>
							<td><?php echo esc_html(get_the_title()); ?></td>
							<td><input type="text" readonly value="<?php echo esc_attr($main_password); ?>" /></td>
							<td>
								<input type="text"
									   name="epwc_secondary_password[<?php echo esc_attr($post_id); ?>]"
									   value="<?php echo esc_attr($secondary_password); ?>" />
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
	</div>
	<?php
}

/**
 * 2) Hook into 'login_form_postpass' so we can rewrite the typed password
 *    if it matches the secondary password before WP sets its 'wp-postpass_' cookie.
 */
add_action('login_form_postpass', 'epwc_rewrite_if_secondary', 1);
function epwc_rewrite_if_secondary() {

	if (isset($_POST['post_password']) && !empty($_POST['post_password'])) {
		$typed_password = sanitize_text_field($_POST['post_password']);

		// Figure out the post ID from 'redirect_to' or the referer
		$redirect_url = !empty($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : wp_get_referer();
		if (!empty($redirect_url)) {
			$post_id = url_to_postid($redirect_url);
		} else {
			$post_id = 0;
		}

		// Fallback if not found
		if (!$post_id && wp_get_referer()) {
			$post_id = url_to_postid(wp_get_referer());
		}

		if ($post_id) {
			$main_password      = get_post_field('post_password', $post_id);
			$secondary_password = get_post_meta($post_id, '_epwc_secondary_password', true);

			if (!empty($secondary_password) && $typed_password === $secondary_password) {
				// Rewrite typed password as the main so WP sets its standard cookie
				$_POST['post_password'] = $main_password;

				// Debug
				add_action('login_head', function() use ($post_id) {
					?>
					<script>console.log("User typed the secondary password for post ID <?php echo esc_js($post_id); ?>. Rewriting to main password so WP sets the standard cookie.");</script>
					<?php
				});
			}
		}
	}
}

/**
 * 3) Optional debugging in the footer (on the front-end).
 *    May not always fire on the login form itself, but helps verify if the plugin is active.
 */
function epwc_debug_footer() {
	?>
	<script>
	console.log("Verbose dev info: If typed password matched the secondary, we rewrote it in $_POST before WP sets the 'wp-postpass_' cookie. Single input, standard WP cookie, two valid passwords!");
	</script>
	<?php
}
add_action('wp_footer', 'epwc_debug_footer');
