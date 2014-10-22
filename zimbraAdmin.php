<?php
require_once ("xmlparse.php");

class zimbraAdmin {
	var $soapheader;
	var $zimbra_error;
	var $zimbra_errno;
	var $zimbra_session;
	var $zimbra_auth;
	var $curlhandle;
        var $zimbraserver;

	function zimbraAdmin($server) {

		$this->curlhandle = curl_init();
		curl_setopt($this->curlhandle, CURLOPT_URL, "https://$server:7071/service/admin/soap");
		curl_setopt($this->curlhandle, CURLOPT_POST, TRUE);
		curl_setopt($this->curlhandle, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($this->curlhandle, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($this->curlhandle, CURLOPT_SSL_VERIFYHOST, FALSE);

	}

	function set_zimbra_header() {
		$this->soapheader = '<soap:Envelope
	xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header>
	  <context xmlns="urn:zimbra"';
                
		if ($this->zimbra_session != 0)
			$this->soapheader .= '>
		    <authToken>' . $this->zimbra_auth . '</authToken>
		    <sessionId id="' . $this->zimbra_session . '">' . $this->zimbra_session . '</sessionId>
		  </context>';
		else
			//$this->soapheader .= '/>';
			$this->soapheader .= '>
			<session></session>
			</context>';
		$this->soapheader .= ' 
	</soap:Header>
	<soap:Body>
	';
	}

	function zimbra_login($adminuser, $adminpass,$adminPreAuthKey,$zimbraDomain) {

		$xml = new xml2Array();
		$this->set_zimbra_header();
                $preauth =    $this->getPreAuth($adminuser,$adminPreAuthKey,$zimbraDomain);
                
                $soapmessage = $this->soapheader . '
                     <AuthRequest xmlns="urn:zimbraAccount">
                        <account by="name">'.$adminuser.$zimbraDomain.'</account>
                        <preauth timestamp="'.time().'000'.'" expires="0">' . $preauth . '</preauth>
                    </AuthRequest>
                    </soap:Body>
                    </soap:Envelope>';

		curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
		if (!($zimbraSOAPResponse = curl_exec($this->curlhandle))) {
			$this->zimbraerrno = curl_errno($this->curlhandle);
			$this->zimbraerror = curl_error($this->curlhandle);
			return false;
		}

		$res = $xml->parse($zimbraSOAPResponse);
		if (!isset ($res['SOAP:ENVELOPE']['SOAP:BODY']['AUTHRESPONSE']))
			return false;
		$x = $res['SOAP:ENVELOPE']['SOAP:BODY']['AUTHRESPONSE'];
                
		$this->zimbra_session = $x['SESSION']['DATA'];
		$this->zimbra_auth = $x['AUTHTOKEN']['DATA'];

		return true;
	}


	function zimbra_search_directory_request($query, $domain = "", $type = "accounts", $limit = 0, $offset = 0, $apply = 0, $max = 0) {
		$xml = new xml2Array();
		$this->set_zimbra_header();
		$soapmessage = $this->soapheader . '
		<SearchDirectoryRequest xmlns="urn:zimbraAdmin"';
		if ($limit != 0)
			$soapmessage .= ' limit="' . $limit . '"';
		if ($offset != 0)
			$soapmessage .= ' offset="' . $offset . '"';
		if ($domain != "")
			$soapmessage .= ' domain="' . $domain . '"';
		if ($max != 0)
			$soapmessage .= ' maxResults="' . $max . '"';
		if ($type != "")
			$soapmessage .= ' types="' . $type . '"';
		$soapmessage .= '>
		<query>' . $query . '</query>
		</SearchDirectoryRequest>
		</soap:Body>
		</soap:Envelope>';
		curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
		if (!($zimbraSOAPResponse = curl_exec($this->curlhandle))) {
			$this->zimbraerrno = curl_errno($this->curlhandle);
			$this->zimbraerror = curl_error($this->curlhandle);
			return false;
		}

		$res = $xml->parse($zimbraSOAPResponse);
	
		if (isset ($res['SOAP:ENVELOPE']['SOAP:BODY']['SEARCHDIRECTORYRESPONSE']))
			return $res['SOAP:ENVELOPE']['SOAP:BODY']['SEARCHDIRECTORYRESPONSE'];
		return false;
	}


	function zimbra_dump_sessions() {

		$xml = new xml2Array();
		$this->set_zimbra_header();
		$soapmessage = $this->soapheader . '
		<DumpSessionsRequest xmlns="urn:zimbraAdmin">
		</DumpSessionsRequest>
		</soap:Body>
		</soap:Envelope>';
		curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
		if (!($zimbraSOAPResponse = curl_exec($this->curlhandle))) {
			$this->zimbraerrno = curl_errno($this->curlhandle);
			$this->zimbraerror = curl_error($this->curlhandle);
			return false;
		}

		$res = $xml->parse($zimbraSOAPResponse);
		if (isset ($res['SOAP:ENVELOPE']['SOAP:BODY']['DUMPSESSIONSRESPONSE']))
			return $res['SOAP:ENVELOPE']['SOAP:BODY']['DUMPSESSIONSRESPONSE'];
		return false;
	}

        


/*@Function:To get searchbyPhrase
  @Param: $uid 
  @Created: Anega Prabhu on 01.03.2013
  @Result: Resultant $res 	
*/
function searchbyPhrase($searchstring=array(),$filePath){
    $lines = file($filePath);

    foreach($lines as $num => $line){
        foreach($searchstring as $needle){
            $pos = strripos($line,$needle);
            if($pos !== false){
                $Exp = explode(':',htmlspecialchars($line));
                return trim(strip_tags($Exp[1]));
            }
        }
    }
}//searchbyPhrase Ends


   /**
    * getPreAuth
    *
    * get the preauth key needed for single-sign on
    *
    * @since        version1.0
    * @access    public
    * @param    string $username username
    * @return    string preauthentication key in hmacsha1 format
    */
    private function getPreAuth($username,$adminPreAuthKey,$zimbraDomain)
    {
        $account_identifier = $username.$zimbraDomain;
        $by_value = 'name';
        $expires = 0;
        $timestamp = time().'000';

         $string = $account_identifier.'|'.$by_value.'|'.$expires.'|'.$timestamp;
        
        return $this->hmacsha1($adminPreAuthKey,$string);
    } // end getPreAuth

    /**
    * hmacsha1
    *
    * generate an HMAC using SHA1, required for preauth
    * 
    * @since        version 1.0
    * @access    public
    * @param    int $key encryption key
    * @param    string $data data to encrypt
    * @return    string converted to hmac sha1 format
    */
    private function hmacsha1($key,$data)
    {
        $blocksize=64;
        $hashfunc='sha1';
        if (strlen($key)>$blocksize)
            $key=pack('H*', $hashfunc($key));
        $key=str_pad($key,$blocksize,chr(0x00));
        $ipad=str_repeat(chr(0x36),$blocksize);
        $opad=str_repeat(chr(0x5c),$blocksize);
        $hmac = pack(
                    'H*',$hashfunc(
                        ($key^$opad).pack(
                            'H*',$hashfunc(
                                ($key^$ipad).$data
                            )
                        )
                    )
                );
        return bin2hex($hmac);
    } // end hmacsha1


// 0: ddmmYYYY_hhii
	// 1: yyyymmddThhiiss
	function TimeToStamp($time,$format=0){
		
		//ddmmYYYY_hhii
		if($format==0){
			$d=substr($time,0,2);
			$m=substr($time,2,2);
			$y=substr($time,4,4);
			$h=substr($time,9,2);
			$i=substr($time,11,2);
		//20100213T142000
		}else if($format==1){
			$y=substr($time,0,4);
			$m=substr($time,4,2);
			$d=substr($time,6,2);
			$h=substr($time,9,2);
			$i=substr($time,11,2);
		}
		
		$t=mktime($h,$i,0,$m,$d,$y);
		echo date('d.m.Y H:i:s',$t);
		return $t;
	}
    



function createAppointment($values,$userId_C){

        require_once CLASS_PATH . 'class.createMeetings.php';
        $objCreateMeetings = new createMeetings();
        
        $ownerDetails = $objCreateMeetings->getUserDetailsId($userId_C);


        $startTime = $objCreateMeetings->getTimeStamp($values['startDate'],$values['startTime']);
        $endTime   = $objCreateMeetings->getTimeStamp($values['endDate'],$values['endTime']);
        $createdDate = time();
        $createdBy = $ownerDetails[0]['user_id'];
        $uid = md5($ownerDetails[0]['email'] . "|" . time());
        $ornanizername = $ownerDetails[0]['firstname'].' '.$ownerDetails[0]['surname'];
        $timeZone = $ownerDetails[0]['mytimezone'];
        $sub   = $values['subject'];
        $desc  = $values['desc'];
        $organizer = $ownerDetails[0]['email'];
        $resources = $values['resource'];

        #Locations
        $values['location']=implode(',',$values['location']); 
        $locationsArray = $objCreateMeetings->getlocationsbyId($values);
        foreach($locationsArray as $location){
           $locations .=  "" .$location['master_sub_name']. ",";
        }
        $locations = rtrim($locations, ',');
        
        #Attendees
        $values['attendee']=implode(',',$values['attendee']); 
        $attendeesArray = $objCreateMeetings->getAttendees($values);
        foreach($attendeesArray as $attendee){
            if($attendee['email'] != $organizer){
                $attendees .=  "" .$attendee['email']. ",";
            }    
        }
        $attendees = rtrim($attendees, ',');

        #Locations
        if(isset($locations) && $locations !=''){
                $displaylocations=explode(',',$locations);
                foreach($displaylocations as $displaylocation){
                        $name= explode('@',$displaylocation);
                        $viewLocation .= ucfirst($name[0]).htmlspecialchars(" <".$displaylocation."> ; ");
                }
               $viewLocation = rtrim($viewLocation, ' ; ');
        }          
        
    $notes = "The following is a new meeting request: Subject: ".$sub."   Organizer: ".$ornanizername."   Location: ".$locations."";
    
    $allday=0;
    if($endTime=='-1'){
            $allday=1;
            $endTime=$startTime;
    }
                        
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage='';
    $soapmessage_m='';
    
                $html=<<<EOF
                            <html><head><style type='text/css'>p { margin: 0; }</style></head><body><div style='font-family: Times New Roman; font-size: 12pt; color: #000000'><span style="font-weight: bold; color:green;">$desc<br><br><br><br></span></div></body></html>
EOF;

		$txt=<<<EOF
                        $notes

EOF;
		$html=str_replace('<','&lt;',$html);
		$txt=str_replace('<','&lt;',$txt);
		$html=utf8_encode($html);
		$txt=utf8_encode($txt);
    

    $soapmessage .= $this->soapheader . '
    <CreateAppointmentRequest echo="1" html="1" neuter="1" forcesend="1" xmlns="urn:zimbraMail">
        <m>
            <su>'.$sub.'</su>
            <mp ct="multipart/alternative">
                    <mp ct="text/plain">
                        <content>'.$txt.'</content>
                    </mp>
                    <mp ct="multipart/related">
                        <mp ct="text/html">
                            <content>'.$html.'</content>
                        </mp>                
                        <attach></attach>
                    </mp>
            </mp>            
           
            <inv id="1" method="Method" compNum="2" rsvp="1"  name="'.$ornanizername.'" isOrg="1" status="NEED">
                <content uid="1" su="">
                    <su></su>
                </content>
                
                <comp status="CONF" fb="B" class="PRI" transp="O" allDay="'.$allday.'" name="'.$sub.'" loc="'.$locations.'" res="'.$locations.'">
                    <desc>'.$txt.'</desc>';
            
                    #Set Organizer
                    $soapmessage .= '<or a="'.$organizer.'" d="'.$ornanizername.'"/>
                    <category></category>
                    <comment></comment>
                    <contact></contact>';
                        
			
                    #Add Locations to Meeting
                    if(isset($locations) && $locations !=''){
			$locations=explode(',',$locations);
			foreach($locations as $location){
				$name= explode('@',$location);
                                $name = ucfirst($name[0]);
				$email=$location;
				
				$soapmessage.='<at role="NON" ptst="NE" cutype="ROO" rsvp="0" a="'.$email.'" d="'.$name.'"/>';
				$soapmessage_m.='<e a="'.$email.'" p="'.$name.'" t="t" add="1"/>';
				
			}
                    }        
                       
                    #Add attendees to Meeting
                    if(isset($attendees) && $attendees !=''){
                       $expAttendees=explode(',',$attendees);
                        foreach($expAttendees as $attendee){
				$name= explode('@',$attendee);
                                $name = ucfirst($name[0]);
				$email=$attendee;
				
				$soapmessage.='<at role="REQ" ptst="NE" rsvp="1" a="'.$email.'" d="'.$name.'"/>';
                                $soapmessage_m.='<e a="'.$email.'" p="'.$name.'" t="t"  add="1"/>';
			}
                    }   
                     
                   $soapmessage .= '
                    <alarm action="DISPLAY">
                        <trigger>
                            <abs d="20140513"/>
                        </trigger>
                        <xprop name="Alarm xparam name" value="Alarm Xparam values"> 
                         <xparam name="Alarm xparam name" value="Alarm Xparam values"/>
                        </xprop> 
                    </alarm>
                    <rec>
                        <add>
                            <exclude>
                                <except rangeType="1" recurId="140513">
                                </except>
                                <cancel rangeType="1" recurId="140513"/>
                                <rule freq="1">
                                     <until d="20140513"/>
                                     <count num="100" />
                                     <interval ival="" />
                                    <bysecond seclist="" />
                                    <byminute minlist="" /> 
                                    <byhour hrlist="" /> 
                                    <byday>
                                        <wkday day="1"/>
                                     </byday>
                                    <bymonthday modaylist="1" />
                                    <byyearday yrdaylist="1" />
                                    <byweekno wklist="1" />
                                    <bymonth molist="1" />
                                    <bysetpos poslist="1" />
                                    <wkst day="1" />
                                    <rule-x-name name="1" value="1" />
                                </rule>
                            </exclude>
                        </add>
                    </rec>
                    <s d="'.date('Ymd\THis',$startTime).'" tz="'.$ownerDetails[0]['mytimezone'].'"/>
                    <e d="'.date('Ymd\THis',$endTime).'" tz="'.$ownerDetails[0]['mytimezone'].'"/>';
                   $soapmessage.='</comp></inv>'.$soapmessage_m;
            $soapmessage.='<tz>1</tz>
        </m>    
    </CreateAppointmentRequest>
    </soap:Body>
    </soap:Envelope>';
  
    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    $res = $xml->parse($zimbraSOAPResponse);
    $zimbraUid = $res['SOAP:ENVELOPE']['SOAP:BODY']['CREATEAPPOINTMENTRESPONSE']['ECHO']['M']['INV']['COMP']['UID'];
    
  if(isset($zimbraUid) && !empty($zimbraUid)){
       return $zimbraUid;
  }
  
}//Craate Appointment End



#Cancel Appointment Starts
function cancelAppointment($intApptId){

    $invId = $intApptId.'-1';
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage='';
    $soapmessage .= $this->soapheader . '
    <CancelAppointmentRequest  id="'.$invId.'"  comp="0"  xmlns="urn:zimbraMail">
    </CancelAppointmentRequest>
    </soap:Body>
    </soap:Envelope>';

    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    
    $res = $xml->parse($zimbraSOAPResponse);
    
    if (isset($res['SOAP:ENVELOPE']['SOAP:BODY'])){
        return $res['SOAP:ENVELOPE']['SOAP:BODY'];
    }
  
}#Cancel Appointment Ends




function sendInviteReply($arrMeetingDetails,$intInvitationId){
    $xml = new xml2Array();
    $this->set_zimbra_header();
    //$invId = '2944';
    //$invId = '3961-3969';
    $strMeetingTitle       = $arrMeetingDetails[0]['meeting_title_decry'];
    $strMeetingOwnerEmail  = $arrMeetingDetails[0]['OwnerEmail'];
    $strMeetingOwnerName   = $arrMeetingDetails[0]['OwnerName'];
    $strAttendeeStatus     = $arrMeetingDetails[0]['strAttendeeStatus'];
   
    #Checking Attendee Status 
    switch ($strAttendeeStatus) {
      case 'ACCEPT':
            $desc  = "Yes, I will attend.";
        break;
      case 'DECLINE':
            $desc  = "No, I won't attend.";
        break;
      case 'TENTATIVE':
            $desc  = "I might attend.";          
        break;
    }
    
 $html=<<<EOF
             <html><head><style type='text/css'>p { margin: 0; }</style></head><body><div><span>$desc<br><br><br><br></span></div></body></html>
EOF;

		$txt=<<<EOF
                        $notes

EOF;
    $html=str_replace('<','&lt;',$html);
    $txt=str_replace('<','&lt;',$txt);
    $html=utf8_encode($html);
    $txt=utf8_encode($txt);
    
    $soapmessage = $this->soapheader . '
    <SendInviteReplyRequest xmlns="urn:zimbraMail" echo="1" html="1" id="'.$intInvitationId.'" idnt="'.$strMeetingOwnerEmail.'" compNum="0" verb="'.$strAttendeeStatus.'" updateOrganizer="1">
            <m>
                    <su>'.ucfirst(strtolower($strAttendeeStatus)).' - '.$strMeetingTitle.'</su>
                    <mp ct="multipart/alternative">
                            <mp ct="text/plain">
                                <content>'.$txt.'</content>
                            </mp>
                            <mp ct="multipart/related">
                                <mp ct="text/html">
                                    <content>'.$html.'</content>
                                </mp>                
                                <attach></attach>
                            </mp>
                    </mp>            
                    <e t="t" a="'.$strMeetingOwnerEmail.'"></e>
                    <e t="t" a="'.$strMeetingOwnerEmail.'" p="'.$strMeetingOwnerName.'"></e>
            </m>
        </SendInviteReplyRequest>
        </soap:Body>
    </soap:Envelope>';

    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    
    $res = $xml->parse($zimbraSOAPResponse);
    if (isset($res['SOAP:ENVELOPE']['SOAP:BODY'])){
        return $res['SOAP:ENVELOPE']['SOAP:BODY'];
    }
  
}//sendInviteReplyNesw End




/*@Function:To get GetAppointment
  @Param: $uid 
  @Created: Anega Prabhu on 01.03.2013
  @Result: Resultant $res 	
*/
function GetAppointment($uid){
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage = $this->soapheader . '
    <GetAppointmentRequest xmlns="urn:zimbraMail">
    <uid>'.strip_tags($uid).'</uid>
    </GetAppointmentRequest>
    </soap:Body>
    </soap:Envelope>';

    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    
    $res = $xml->parse($zimbraSOAPResponse);
    if (isset($res['SOAP:ENVELOPE']['SOAP:BODY']['GETAPPOINTMENTRESPONSE'])){
        return $res['SOAP:ENVELOPE']['SOAP:BODY']['GETAPPOINTMENTRESPONSE'];
    }
  
}//GetAppointment End


#Get Message Request
function GetMessageRequest($uid){
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage = $this->soapheader . '
    <GetMsgRequest xmlns="urn:zimbraMail">
    <m id="3961-1">
        
    </m>
    </GetMsgRequest>
    </soap:Body>
    </soap:Envelope>';

    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    
    $res = $xml->parse($zimbraSOAPResponse);
    if (isset($res['SOAP:ENVELOPE']['SOAP:BODY']['GETAPPOINTMENTRESPONSE'])){
        return $res['SOAP:ENVELOPE']['SOAP:BODY']['GETAPPOINTMENTRESPONSE'];
    }
  
}#getmessageRequest


function updateAppointment($values,$userId_C){
    $zimbraUid = $values['zimbraUid'];
    if(isset($zimbraUid) && !empty($zimbraUid)){
        $arrAppointmentDetails =   $this->GetAppointment($zimbraUid);
       
        $intApptId = $arrAppointmentDetails['APPT']['ID'];
        $UID = $arrAppointmentDetails['APPT']['UID'];
    }    
    //pr($arrAppointmentDetails);exit;
        require_once CLASS_PATH . 'class.createMeetings.php';
        $objCreateMeetings = new createMeetings();
        
        $ownerDetails = $objCreateMeetings->getUserDetailsId($userId_C);


        $startTime = $objCreateMeetings->getTimeStamp($values['startDate'],$values['startTime']);
        $endTime   = $objCreateMeetings->getTimeStamp($values['endDate'],$values['endTime']);
        $createdDate = time();
        $createdBy = $ownerDetails[0]['user_id'];
        $uid = md5($ownerDetails[0]['email'] . "|" . time());
        $ornanizername = $ownerDetails[0]['firstname'].' '.$ownerDetails[0]['surname'];
        $timeZone = $ownerDetails[0]['mytimezone'];
        $sub   = $values['subject'];
        $desc  = $values['desc'];
        $organizer = $ownerDetails[0]['email'];
        $resources = $values['resource'];

        #Locations
        $values['location']=implode(',',$values['location']); 
        $locationsArray = $objCreateMeetings->getlocationsbyId($values);
        foreach($locationsArray as $location){
           $locations .=  "" .$location['master_sub_name']. ",";
        }
        $locations = rtrim($locations, ',');
        
        #Attendees
        $values['attendee']=implode(',',$values['attendee']); 
        $attendeesArray = $objCreateMeetings->getAttendees($values);
        foreach($attendeesArray as $attendee){
            if($attendee['email'] != $organizer){
                $attendees .=  "" .$attendee['email']. ",";
            }    
        }
        $attendees = rtrim($attendees, ',');

        #Locations
        if(isset($locations) && $locations !=''){
                $displaylocations=explode(',',$locations);
                foreach($displaylocations as $displaylocation){
                        $name= explode('@',$displaylocation);
                        $viewLocation .= ucfirst($name[0]).htmlspecialchars(" <".$displaylocation."> ; ");
                }
               $viewLocation = rtrim($viewLocation, ' ; ');
        }          
        
    $notes = "The following meeting has been modified: Subject: ".$sub."   Organizer: ".$ornanizername."   Location: ".$locations."";
    
    $allday=0;
    if($endTime=='-1'){
            $allday=1;
            $endTime=$startTime;
    }
                        
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage='';
    $soapmessage_m='';
    
                $html=<<<EOF
                            <html><head><style type='text/css'>p { margin: 0; }</style></head><body><div style='font-family: Times New Roman; font-size: 12pt; color: #000000'><span style="font-weight: bold; color:green;">$desc<br><br><br><br></span></div></body></html>
EOF;

		$txt=<<<EOF
                        $notes

EOF;
		$html=str_replace('<','&lt;',$html);
		$txt=str_replace('<','&lt;',$txt);
		$html=utf8_encode($html);
		$txt=utf8_encode($txt);
                
    $xml = new xml2Array();
    $this->set_zimbra_header();
    $soapmessage='';
	if (is_array($appt['inv'][0]['comp'][0]['recur'])) return false;
		$exceptIdstr = '';
		if($needexceptID){
			$exceptIdstr='		<exceptId
									d="'.$appt['inv'][0]['comp'][0]['s_attribute_d'][0].'" 
									tz="'.htmlentities($appt['inv'][0]['comp'][0]['s_attribute_tz'][0]).'"/>';
		}
                $invId = $intApptId;
		$soapmessage .= $this->soapheader . '
    <CounterAppointmentRequest id="'.$invId.'" comp="0" neuter="1" echo="1" xmlns="urn:zimbraMail">
      <m>
            <su>'.$sub.'</su>
            <mp ct="multipart/alternative">
                    <mp ct="text/plain">
                        <content>'.$txt.'</content>
                    </mp>
                    <mp ct="multipart/related">
                        <mp ct="text/html">
                            <content>'.$html.'</content>
                        </mp>                
                        <attach></attach>
                    </mp>
            </mp>            
           
            <inv id="1" method="Method" compNum="2" rsvp="1"  name="'.$ornanizername.'" isOrg="1" status="NEED" uid="'.$UID.'">
                <content uid="'.$UID.'" su="">
                    <su></su>
                </content>
                
                <comp status="CONF" fb="B" class="PRI" transp="O" allDay="'.$allday.'" name="'.$sub.'" loc="'.$locations.'" res="'.$locations.'">
                    <desc>'.$txt.'</desc>';
            
                    #Set Organizer
                    $soapmessage .= '<or a="'.$organizer.'" d="'.$ornanizername.'"/>
                    <category></category>
                    <comment></comment>
                    <contact></contact>';
                        
			
                    #Add Locations to Meeting
                    if(isset($locations) && $locations !=''){
			$locations=explode(',',$locations);
			foreach($locations as $location){
				$name= explode('@',$location);
                                $name = ucfirst($name[0]);
				$email=$location;
				
				$soapmessage.='<at role="NON" ptst="NE" cutype="ROO" rsvp="0" a="'.$email.'" d="'.$name.'"/>';
				$soapmessage_m.='<e a="'.$email.'" p="'.$name.'" t="t" add="1"/>';
				
			}
                    }        
                       
                    #Add attendees to Meeting
                    if(isset($attendees) && $attendees !=''){
                       $expAttendees=explode(',',$attendees);
                        foreach($expAttendees as $attendee){
				$name= explode('@',$attendee);
                                $name = ucfirst($name[0]);
				$email=$attendee;
				
				$soapmessage.='<at role="REQ" ptst="NE" rsvp="1" a="'.$email.'" d="'.$name.'"/>';
                                $soapmessage_m.='<e a="'.$email.'" p="'.$name.'" t="t"  add="1"/>';
			}
                    }   
                     
                   $soapmessage .= '
                    <s d="'.date('Ymd\THis',$startTime).'" tz="'.$ownerDetails[0]['mytimezone'].'"/>
                    <e d="'.date('Ymd\THis',$endTime).'" tz="'.$ownerDetails[0]['mytimezone'].'"/>';
                   $soapmessage.='</comp></inv>'.$soapmessage_m;
            $soapmessage.='<tz>1</tz>
        </m>    
    </CounterAppointmentRequest>
    </soap:Body>
    </soap:Envelope>';
		//echo $soapmessage;exit;
		//$this->debug=true;
    curl_setopt($this->curlhandle, CURLOPT_POSTFIELDS, $soapmessage);
    if(!($zimbraSOAPResponse = curl_exec($this->curlhandle))){
          $this->zimbraerrno = curl_errno($this->curlhandle);
          $this->zimbraerror = curl_error($this->curlhandle);
        return false;
    }
    $res = $xml->parse($zimbraSOAPResponse);
    //pr($res);exit;

		if($response){
			return true;
		}else{
			return false;
		}
	
    
}


}//End of Class



?>
