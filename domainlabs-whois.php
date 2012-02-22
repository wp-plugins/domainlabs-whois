<?php
/**
 * @package Domainlabs_Whois
 * @version 1.0
 */
/*
Plugin Name: Domainlabs Domain Whois
Plugin URI: http://wordpress.org/extend/plugins/domainlabs-whois/
Description: DomainLabs Domain Whois Plugin.
Author: Bahri Meriç CANLI
Version: 1.0
Author URI: http://www.domainlabs.eu/
*/
 
if (!class_exists("DomainLabsWhois")) {
	class DomainLabsWhois {

		function whoisForm($domain="")
		{
			
		$domainwhoisAdminOptions = $this->get_domainwhoisOptions();

		$widget = '
		<div>
		<div>Domain whois</div>
			<form action="'. get_bloginfo('wpurl').$domainwhoisAdminOptions['whois-redirect-url'].'" id="wpwhoisfor" method="post" style="margin: 0px;"> 
				<input id="wpwhoisdomain" name="domain" type="text" class="whois-text" value="'.$domain.'" /> 
				<input name="lookup" type="submit" value="Whois" class="whois-submit" />
			</form> 
		</div>
		';

		return $widget;
		}

		     

		function addHeaderCode() {
			echo '<link type="text/css" rel="stylesheet" href="' . get_bloginfo('wpurl') . '/wp-content/plugins/domainlabs-whois/domainlabs-whois.css" />' . "\n";		
		}
		 
		function widget_Whois($args) {
		  extract($args);
		  echo $before_widget;
		  echo $before_title;
		  //Whois
		  echo $after_title;
		  echo $this->whoisForm();
		  echo $after_widget;
		}
		
		function control_Whois(){
    		echo 'This widget is not have a options';
  		}

/*********************************************************************/  	 		
	function get_whois_server_detail($domain) {
		
		$extension = substr($domain, strrpos($domain, ".")+1);
		
		switch ($extension) {
			case "tr":
				$server["host"] = "whois.nic.tr";
				$server["notfound"] = "No match found for";
				break;
			case "com":	
				$server["host"] = "whois.verisign-grs.com";
				$server["notfound"] = "No match for";
				break;
			case "net":	
				$server["host"] = "whois.verisign-grs.com";
				$server["notfound"] = "No match for";
				break;
			case "name":	
				$server["host"] = "whois.nic.name";
				$server["notfound"] = "No match";
				break;		
			case "info":	
				$server["host"] = "whois.afilias.net";
				$server["notfound"] = "NOT FOUND";
				break;		
			case "org":	
				$server["host"] = "whois.pir.org";
				$server["notfound"] = "NOT FOUND";
				break;	
			case "ru":	
				$server["host"] = "whois.ripn.net";
				$server["notfound"] = "No entries found for the selected source";
				break;	
			case "su":	
				$server["host"] = "whois.ripn.net";
				$server["notfound"] = "No entries found for the selected source";
				break;					
			case "tv":	
				$server["host"] = "tvwhois.verisign-grs.com";
				$server["notfound"] = "No match for";
				break;		
			case "biz":	
				$server["host"] = "whois.biz";
				$server["notfound"] = "Not found";
				break;									
								
			default:	
				$server["host"] = "whois.ripe.net";
				$server["notfound"] = "No entries found";
				break;		
		}
		
	return 	$server;
	}

	function whois($url,$domain_ip){
		$sock = fsockopen($url, 43, $errno, $errstr);
	    if (!$sock) exit("$errno($errstr)");
	   	else {
	     fputs ($sock, $domain_ip."\r\n");
	     $text = "";
	     while (!feof($sock))
	     {
	       $text .= fgets ($sock, 128)."<br>";
	     }
	    fclose ($sock);
	    $pattern = "|ReferralServer: whois://([^\n<:]+)|i";
	    preg_match($pattern, $text, $out);
	    if(!empty($out[1])) return whois($out[1], $domain_ip);
	    else return $text;
	    }
  	}
  	
  	
  	
 	function whoisResults($domain) {
		$serverDetail = $this->get_whois_server_detail($domain);
		$answer = $this->whois($serverDetail["host"],$domain);
		if (strpos ($answer, $serverDetail["notfound"])==FALSE){
				return $answer;	
		}
		else return "Domain not found";
	} 	
  		
/*********************************************************************/  	

	function whoisresult_callback($content) {
		$results = "";
		if (strpos($content,'%%whoisresults%%')!== false) {
				$domain = stripslashes(trim($_POST['domain']));
				if(isset($_POST['lookup'])) {
					
					$results .= $this->whoisForm($domain);
					$results .= '<div class="whois-results"><pre>';
					$results .= $this->whoisResults($domain);
					$results .= "</pre></div>";
					
				}
				else $results .= $this->whoisForm();
			
		}
		
		$content = str_replace('%%whoisresults%%', $results, $content);
	return $content;
	}

/*********************************************************************/  		
  		
  		function get_domainwhoisOptions() {
			$domainwhoisAdminOptions = array(
				'whois-redirect-url' => "/whois"
				);
				
			$domainwhoisOptions = get_option("domainwhoisAdminOptions");
			if ( !empty($domainwhoisOptions) ) {
				foreach ( $domainwhoisOptions as $key => $option ) {
					$domainwhoisAdminOptions[$key] = $option;
				}
			}
			update_option("domainwhoisAdminOptions", $domainwhoisAdminOptions);
		return $domainwhoisAdminOptions;
		}
  		
  		function print_domainwhoisAdminPage()
		{
	
	
		$domainwhoisAdminOptions = $this->get_domainwhoisOptions();
	
		if (isset($_POST['update_domainwhoisSettings'])) {
	
			if (isset($_POST['ll_whois-redirect-url'])) {
				$domainwhoisAdminOptions['whois-redirect-url'] = $_POST['ll_whois-redirect-url'];
			}
			
			update_option("domainwhoisAdminOptions", $domainwhoisAdminOptions);
			?>
	<div class="updated"><p><strong><?php _e("Settings Updated.", "domainwhois");?></strong></p></div>
<?php
		}
	
?>
		<div class="wrap">
		<div id="icon-plugins" class="icon32"><br /></div><h2>DomainLabs Domain Whois Settings</h2>
		
		<form method="post" action="<?php echo esc_attr($_SERVER["REQUEST_URI"]); ?>">
		<input type='hidden' name='option_page' value='general' />
		<input type="hidden" name="action" value="update" />
		
		<table class="form-table">
		<tr valign="top">
			<th scope="row"><label for="siteurl">Redirect Address (URL)</label></th>
			<td><input name="ll_whois-redirect-url" type="text" id="whois-redirect" value="<?php echo esc_attr($domainwhoisAdminOptions['whois-redirect-url']); ?>" class="regular-text code" />
			<span class="description">without <?php  echo get_bloginfo('wpurl'); ?> </span>	</td>
		</tr>
		</table>
		
		<p class="submit"><input type="submit" name="update_domainwhoisSettings" id="submit" class="button-primary" value="Save Changes"  /></p></form>
		
		
		
		</form>
		</div>
<?php

		}
		
/*********************************************************************/		
  		
  		function adminMenu() {
 		    add_options_page("DomainLabs Domain Whois", "Domain Whois", 1, "Domain-Whois", array(&$this, "print_domainwhoisAdminPage"));
  		}
  		
	}
}  //End Class DomainLabsWhois


if (class_exists("DomainLabsWhois")) {
	$dl_domainLabsWhois = new DomainLabsWhois();
}
 
function whois_init() {
	global $dl_domainLabsWhois;
    register_sidebar_widget(__('Domain Whois'), array(&$dl_domainLabsWhois, 'widget_Whois'));
    register_widget_control(__('Domain Whois'), array(&$dl_domainLabsWhois, 'control_Whois'));
}

if (isset($dl_domainLabsWhois)) {
	add_action('wp_head', array(&$dl_domainLabsWhois, 'addHeaderCode'), 1);
	add_action('admin_menu', array(&$dl_domainLabsWhois, 'adminMenu'), 1);
	add_action('plugins_loaded', 'whois_init');
	add_filter('the_content',array(&$dl_domainLabsWhois, 'whoisresult_callback'), 7);
}
?>