<?php
/**
 * @package Domainlabs_Whois
 * @version 1.0.3
 */
/*
Plugin Name: Domainlabs Domain Whois
Plugin URI: http://wordpress.org/extend/plugins/domainlabs-whois/
Description: DomainLabs Domain Whois Plugin.
Author: Bahri Meriç CANLI
Version: 1.0.3
Author URI: http://www.bahri.info/
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
</br>
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
		
		if($this->is_ipaddress($domain)) $extension = "ipaddress";
		else $extension = substr($domain, strrpos($domain, ".")+1);
		
		

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
			case "us":	
				$server["host"] = "whois.nic.us";
				$server["notfound"] = "Not found:";
				break;		
			case "uk":	
				$server["host"] = "whois.nic.uk";
				$server["notfound"] = "No match for";
				break;	
			case "ch":	
				$server["host"] = "whois.nic.ch";
				$server["notfound"] = "We do not have an entry in our database matching your query.";
				break;		
			case "ipaddress":
				$server["host"] = "whois.ripe.net";
				$server["notfound"] = "No entries found";
				break;
			default:	
				$server["host"] = "whois.iana.org";
				$server["notfound"] = "this server does not have
% any data for";
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
	    }
		
	
	    $text = $this->toUtf8($text);

	    $pattern = "|Whois Server: ([^\n<:]+)|i";
	    preg_match($pattern, $text, $out);

	    $pattern2 = "|whois: ([^\n<:]+)|i";
	    preg_match($pattern2, $text, $out2);

	    if(!empty($out[1])) 
		$text.= $this->whois($out[1], $domain_ip);
	    elseif(!empty($out2[1])) 
		$text = $this->whois(trim($out2[1]), $domain_ip);
	    
	return $text;    
  	}


    function is_ipaddress($string) {

   if (preg_match(
'/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:[.](?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/',
   $string)) return true;
else return false;

    }	  	

    function is_utf8($string) { 
       
        // From http://w3.org/International/questions/qa-forms-utf-8.html 
        return preg_match('%^(?: 
              [\x09\x0A\x0D\x20-\x7E]            # ASCII 
            | [\xC2-\xDF][\x80-\xBF]             # non-overlong 2-byte 
            |  \xE0[\xA0-\xBF][\x80-\xBF]        # excluding overlongs 
            | [\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}  # straight 3-byte 
            |  \xED[\x80-\x9F][\x80-\xBF]        # excluding surrogates 
            |  \xF0[\x90-\xBF][\x80-\xBF]{2}     # planes 1-3 
            | [\xF1-\xF3][\x80-\xBF]{3}          # planes 4-15 
            |  \xF4[\x80-\x8F][\x80-\xBF]{2}     # plane 16 
        )*$%xs', $string); 
       
    } 



	function toUtf8($content) { 
	   if(!$this->is_utf8($content)) {
  /// for iso8859-9
   		
	$content= str_replace ( array ("İ", "\u0130", "\xDD", "İ" ), "İ", $content);
	$content= str_replace ( array ("ı", "\u0131", "\xFD", "ı" ), "ı", $content);
	$content= str_replace ( array ("Ğ", "\u011e", "\xD0", "Ğ" ), "Ğ", $content);
	$content= str_replace ( array ("ğ", "\u011f", "\xF0", "ğ" ), "ğ", $content);
	$content= str_replace ( array ("Ü", "\u00dc", "\xDC", "Ü" ), "Ü", $content);
	$content= str_replace ( array ("ü", "\u00fc", "\xFC", "ü" ), "ü", $content);
	$content= str_replace ( array ("Ş", "\u015e", "\xDE", "Ş" ), "Ş", $content);
	$content= str_replace ( array ("ş", "\u015f", "\xFE", "ş" ), "ş", $content);
	$content= str_replace ( array ("Ö", "\u00d6", "\xD6", "Ö" ), "Ö", $content);
	$content= str_replace ( array ("ö", "\u00f6", "\xF6", "ö" ), "ö", $content);
	$content= str_replace ( array ("Ç", "\u00c7", "\xC7", "Ç" ), "Ç", $content);
	$content= str_replace ( array ("ç", "\u00e7", "\xE7", "ç" ), "ç", $content);


	   }
	
	return $content;
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
