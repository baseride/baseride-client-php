<?php
define('BASERIDE_URL','https://baseride.com/');
define('BASERIDEAPI_URL',BASERIDE_URL.'api/v2/');
define('BASERIDEAPI_SECRETCODE','XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
define('BASERIDEAPI_PUBLICCODE','XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX');
define('BASERIDEAPI_REDIRECT_URI','http://127.0.0.1/');

class Baseride {
    function __construct($user,$password,$opts=false) {
        if(!$opts) {
            $opts = array();
        }
        $o = array_slice($opts,0,NULL,true);
        if( !array_key_exists('BASERIDE_URL',$o) ) $o['BASERIDE_URL'] = BASERIDE_URL;
        if( !array_key_exists('BASERIDEAPI_URL',$o) ) $o['BASERIDEAPI_URL'] = BASERIDEAPI_URL;
        if( !array_key_exists('BASERIDEAPI_SECRETCODE',$o) ) $o['BASERIDEAPI_SECRETCODE'] = BASERIDEAPI_SECRETCODE;
        if( !array_key_exists('BASERIDEAPI_PUBLICCODE',$o) ) $o['BASERIDEAPI_PUBLICCODE'] = BASERIDEAPI_PUBLICCODE;
        if( !array_key_exists('BASERIDEAPI_REDIRECT_URI',$o) ) $o['BASERIDEAPI_REDIRECT_URI'] = BASERIDEAPI_REDIRECT_URI;
        $this->user = $user;
        $this->password = $password;
        $this->opts = $o;
        $this->tokens = false;
        $this->last_code = false;
        $this->tokenfile = false;
    }
    function header_callback($channel,$data) {
            if( strpos($data,'HTTP') === 0 ) {
                $l = explode(' ',$data);
                $this->last_code = $l[1];
            }
            return strlen($data);
    }
    function authorize() {
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$this->opts['BASERIDE_URL'].'oauth2/authorize/?response_type=code&client_id='.$this->opts['BASERIDEAPI_PUBLICCODE'].'&redirect_uri='.$this->opts['BASERIDEAPI_REDIRECT_URI']);
        curl_setopt($ch,CURLOPT_USERPWD,$this->user.':'.$this->password);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION,false);
        curl_setopt($ch,CURLOPT_HEADER,true);
        $ret = curl_exec($ch);
        curl_close($ch);
        $ret = explode("\r\n",$ret);
        $loc = false;
        foreach($ret as $ln) {
            if( stripos($ln,'HTTP') === 0 ) {
                $l = explode(' ',$ln);
                $this->last_code = $l[1];
            }
            if( stripos($ln,'location:') === 0 ) {
                $loc = substr($ln,10);
                break;
            }
        }
        if( !$loc )
            return false;
        $code = stripos($loc,'code=');
        if( !$code )
            return false;
        $code = substr($loc,$code+5);
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$this->opts['BASERIDE_URL'].'oauth2/token/?client_id='.$this->opts['BASERIDEAPI_PUBLICCODE'].'&client_secret='.$this->opts['BASERIDEAPI_SECRETCODE'].'&code='.$code.'&grant_type=authorization_code&redirect_uri='.$this->opts['BASERIDEAPI_REDIRECT_URI']);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION,false);
        curl_setopt($ch,CURLOPT_HEADER,false);
        $that = $this;
        curl_setopt($ch,CURLOPT_HEADERFUNCTION,array($this, 'header_callback'));
        $ret = curl_exec($ch);
        curl_close($ch);
        $tokens = json_decode($ret,true);
        if( array_key_exists('access_token',$tokens) && array_key_exists('refresh_token',$tokens) ) {
            $this->tokens = $tokens;
            $this->storetokens();
            return $this->tokens;
        }
    }
    function storetokens($tokenfile=true) {
        if( $tokenfile === false ) {
            if( $this->tokenfile ) {
                unlink($this->tokenfile);
            }
            $this->tokenfile = false;
            return;
        }
        if( $tokenfile === true ) {
            if( $this->tokenfile ) {
                if( $this->tokens ) {
                    file_put_contents($this->tokenfile,json_encode($this->tokens));
                }
            }
            return;
        }
        if( $tokenfile !== $this->tokenfile ) {
            if( $this->tokenfile ) {
                unlink($this->tokenfile);
            }
        }
        $this->tokenfile = $tokenfile;
        if( file_exists($this->tokenfile) ) {
            $this->tokens = json_decode(file_get_contents($this->tokenfile),true);
        } else {
            $this->storetokens(true);
        }
    }

    function ensure($refresh=false) {
        if( !$this->tokens || !array_key_exists('access_token',$this->tokens) || !array_key_exists('refresh_token',$this->tokens) ) {
            return $this->authorize();
        }
        if( !$refresh ) {
            return $this->tokens;
        }
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$this->opts['BASERIDE_URL'].'oauth2/token/?client_id='.$this->opts['BASERIDEAPI_PUBLICCODE'].'&client_secret='.$this->opts['BASERIDEAPI_SECRETCODE'].'&grant_type=refresh_token&refresh_token='.$this->tokens['refresh_token'].'&redirect_uri='.$this->opts['BASERIDEAPI_REDIRECT_URI']);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION,false);
        curl_setopt($ch,CURLOPT_HEADER,false);
        $that = $this;
        curl_setopt($ch,CURLOPT_HEADERFUNCTION,array($this, 'header_callback'));
        $ret = curl_exec($ch);
        curl_close($ch);
        if( !$ret ) {
            return $this->authorize();
        }
        $tokens = json_decode($ret,true);
        if( !array_key_exists('access_token',$tokens) || !array_key_exists('refresh_token',$tokens) ) {
            return $this->authorize();
        }
        $this->tokens = $tokens;
        $this->storetokens();
        return $this->tokens;
    }
    function get($path,$opts=false,$try=1) {
        if( !$this->ensure() )
            return false;
        if(!$opts) {
            $opts = array();
        }
        $o = array_slice($opts,0,NULL,true);
        $o['access_token'] = $this->tokens['access_token'];
        $pars = "";
        foreach($o as $k=>$v) {
            $pars .= $k.'='.urlencode($v).'&';
        }
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$this->opts['BASERIDEAPI_URL'].$path.'?'.$pars);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION,true);
        curl_setopt($ch,CURLOPT_HEADER,false);
        $that = $this;
        curl_setopt($ch,CURLOPT_HEADERFUNCTION,array($this, 'header_callback'));
        $ret = curl_exec($ch);
        curl_close($ch);
        if( !$ret ) {
            if( $this->last_code != '404' ) {
                if( $try ) {
                    $this->ensure(true);
                    return $this->get($path,$opts,$try-1);
                }
            }
        }
        return $ret;
    }
    function post($path,$opts=false,$val=array(),$method='POST',$try=1) {
        if( !$this->ensure() )
            return false;
        if(!$opts) {
            $opts = array();
        }
        $o = array_slice($opts,0,NULL,true);
        $o['access_token'] = $this->tokens['access_token'];
        $pars = "";
        foreach($o as $k=>$v) {
            $pars .= $k.'='.urlencode($v).'&';
        }
        $value = json_encode($val);
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$this->opts['BASERIDEAPI_URL'].$path.'?'.$pars);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION,true);
        curl_setopt($ch,CURLOPT_HEADER,false);
        $that = $this;
        curl_setopt($ch,CURLOPT_HEADERFUNCTION,array($this, 'header_callback'));
        curl_setopt($ch,CURLOPT_POST,true);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$value);
        curl_setopt($ch,CURLOPT_HTTPHEADER,array(
            'Content-Type: application/json',
            'Content-Length: '.strlen($value),
            'X-HTTP-Method-Override: '.$method,
        ));
        $ret = curl_exec($ch);
        curl_close($ch);
        if( !$ret ) {
            if( $try ) {
                if( $this->last_code >= 400 ) {
                    $this->ensure(true);
                    return $this->post($path,$opts,$val,$method,$try-1);
                }
            }
        }
        return $ret;
    }

    function get_objects($entrypoint,$offset=0,$limit=20) {
        $v = $this->get($entrypoint,array(
            'offset'=>$offset,
            'limit'=>$limit,
        ));
        if( $v ) return json_decode($v,true);
        return false;
    }
    function get_object($entrypoint,$id) {
        $v = $this->get($entrypoint.$id.'/');
        if( $v ) return json_decode($v,true);
        return false;
    }
    function create_object($entrypoint,$patch) {
        $v = $this->post($entrypoint,false,$patch);
        if( $v ) return json_decode($v,true);
        return false;
    }
    function patch_object($entrypoint,$id,$patch) {
        $v = $this->post($entrypoint.$id.'/',false,$patch,'PATCH');
        if( $v ) return json_decode($v,true);
        return false;
    }
    function delete_object($entrypoint,$id) {
        $v = $this->post($entrypoint.$id.'/',false,array(),'DELETE');
        if( $v ) return json_decode($v,true);
        if( $this->last_code == 204 )
            return true;
        return false;
    }
    private static $instances = array();
    static function instance($user,$password,$opts=false) {
        if( array_key_exists($user,self::$instances) ) {
            return self::$instances[$user];
        }
        self::$instances[$user] = new Baseride($user,$password,$opts);
        return self::$instances[$user];
    }
    static function longinstance($user,$password,$opts=false) {
        if( array_key_exists($user,self::$instances) ) {
            return self::$instances[$user];
        }
        self::$instances[$user] = new Baseride($user,$password,$opts);
        self::$instances[$user]->storetokens(sys_get_temp_dir().'/tokens_'.$user.'.json');
        return self::$instances[$user];
    }
}

/*
if( $argc >= 3 ) {
    $baseride = new Baseride($argv[1],$argv[2]);
    $t = file_get_contents('tokens.json');
    $renew = false;
    if( $t ) {
        $baseride->tokens = json_decode($t,true);
    } else {
        $renew = true;
    }
    $me = $baseride->get_objects('profile/whoami/')['objects'][0];
    $profile = $baseride->get_object('profile/userprofile/',$me['id']);
    echo json_encode($profile),"\n";
    echo "token:",$baseride->tokens['access_token'],"\n";
    $baseride->ensure($renew);
    echo "new token:",$baseride->tokens['access_token'],"\n";
    $t = json_encode($baseride->tokens);
    file_put_contents('tokens.json',$t);
    $v = $baseride->create_object('logistics/task/',array(
        'name'=>'the test',
        'enterprise'=>$profile['enterprise'],
    ));
    if( !$v ) {
        echo "Error?",$baseride->last_code,"\n";
        exit(1);
    }
    echo "Created:",json_encode($v),"\n";
    $v = $baseride->patch_object('logistics/task/',$v['id'],array(
        'name'=>'the test patched',
    ));
    if( !$v ) {
        echo "Error?",$baseride->last_code,"\n";
        exit(1);
    }
    echo "Patched:",json_encode($v),"\n";
    $d = $baseride->delete_object('logistics/task/',$v['id']);
    if( !$d ) {
        echo "Error?",$baseride->last_code,"\n";
        exit(1);
    }
    echo "Deleted:",$v['id'],"\n";
} else {
    echo "callme ".$argv[0]." user password\n";
}
*/
?>