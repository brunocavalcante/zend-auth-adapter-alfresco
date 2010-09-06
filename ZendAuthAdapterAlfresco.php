<?php
/**
 * Zend Auth Adapter Alfresco
 *
 * Adapter to make the authentication through Alfresco <http://www.alfresco.com/> webservice.
 *
 * @author Bruno Cavalcante <brunofcavalcante@gmail.com>
 * @version 0.1
*/

/**
 * @see Zend_Auth_Adapter_Interface
 */
class ZendAuthAdapterAlfresco implements Zend_Auth_Adapter_Interface
{
    protected $_username;
    protected $_password;
    protected $_wsdlAddress;
    protected $_response;
    protected $_result;
    
    /**
     * Sets username and password for authentication
     *
     * @return void
     */
    public function __construct($username, $password, $wsdlAddress)
    {
        $this->setUsername($username);
        $this->setPassword($password);
        $this->setWsdlAddress($wsdlAddress);
        $this->setDefaultResult();
    }
    
    private function setDefaultResult()
    {
        $this->_result = array('code' => null, 'messages' => array(), 'identity' => null);
    }
 
    private function getUsername()
    {
        return $this->_username;
    }
    
    private function setUsername($username)
    {
        $this->_username = $username;
    }
    
    private function getPassword()
    {
        return $this->_password;
    }
    
    private function setPassword($password)
    {
        $this->_password = $password;
    }
    
    private function getWsdlAddress()
    {
        return $this->_wsdlAddress;
    }
    
    private function setWsdlAddress($wsdlAddress)
    {
        $this->_wsdlAddress = $wsdlAddress;
    }
    
    private function getResponse()
    {
        return $this->_response;
    }
    
    private function setResponse($response)
    {
        $this->_response = $response;
    }
    
    private function getResultCode()
    {
        return $this->_result['code'];
    }
    
    private function setResultCode($code)
    {
        $this->_result['code'] = $code;
    }
    
    private function getResultMessages()
    {
        return $this->_result['messages'];
    }
    
    private function addResultMessage($message)
    {
        $this->_result['messages'][] = $message;
    }
    
    private function getResultIdentity()
    {
        return $this->_result['identity'];
    }
    
    private function setResultIdentity($identity)
    {
        $this->_result['identity'] = $identity;
    }
    
    /**
     * Performs an authentication attempt
     *
     * @throws Zend_Auth_Adapter_Exception If authentication cannot be performed
     * @return Zend_Auth_Result
     */
    public function authenticate()
    {
        try {
            $this->authenticateOnAlfresco();
            $this->setApplicationUser();
        } catch (Exception $e) {
            $this->throwAuthorizationError($e);
        }
        $code = $this->getResultCode();
        $identity = $this->getResultIdentity();
        $messages = $this->getResultMessages();
        return new Zend_Auth_Result($code, $identity, $messages);
    }
    
    private function authenticateOnAlfresco()
    {
        $username = $this->getUsername();
        $password = $this->getPassword();
        $soapClient = $this->getSoapClient();
        
        $response = $soapClient->startSession(array('username' => $username, 'password' => $password));
        
        $this->setResponse($response);
    }
    
    private function getSoapClient()
    {
        $soap_client = new Zend_Soap_Client($this->getWsdlAddress());
        return $soap_client;
    }
    
    private function setApplicationUser()
    {
        $messages = array();
        $code = $this->getSuccessCode();
        $identity = $this->getIdentityFromResponse();
        
        $this->setResultCode($code);
        $this->setResultIdentity($identity);
    }
    
    private function getSuccessCode()
    {
        return Zend_Auth_Result::SUCCESS;
    }
    
    private function getIdentityFromResponse()
    {
        $identity = array();
        $identity['username'] = $this->getUsernameFromResponse();
        $identity['ticket'] = $this->getTicketFromResponse();
        $identity['sessionid'] = $this->getSessionIdFromResponse();
        
        return $identity;
    }
    
    private function getUsernameFromResponse()
    {
        return $this->getResponse()->startSessionReturn->username;
    }
    
    private function getTicketFromResponse()
    {
        return $this->getResponse()->startSessionReturn->ticket;
    }
    
    private function getSessionIdFromResponse()
    {
        return $this->getResponse()->startSessionReturn->sessionid;
    }
    
    private function throwAuthorizationError($exception)
    {
        $code = $this->getDefaultErrorCode();
        if ($this->isConnectionFailure()) {
            $code = $this->getConnectionFailureErrorCode();
        } elseif ($this->isAlfrescoError()) {
            $code = $this->getAlfrescoErrorCode($exception);
        }
        $this->setResultCode($code);
    }
    
    private function getDefaultErrorCode()
    {
        Zend_Auth_Result::FAILURE_UNCATEGORIZED;
    }
    
    private function isConnectionFailure($exception)
    {
        return isset($exception->faultcode);
    }
    
    private function getConnectionFailureErrorCode()
    {
        return Zend_Auth_Result::FAILURE;
    }
    
    private function isAlfrescoError($exception)
    {
        return isset($exception->detail);
    }
    
    private function getAlfrescoErrorCode($exception)
    {
        $errorCode = $exception->detail->AuthenticationFault->errorCode;
        switch ($errorCode) {
           case 100:
               $code = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
               break;
           default:
               $code = Zend_Auth_Result::FAILURE_UNCATEGORIZED;
               break;
        }
        return $code;
    }
}
