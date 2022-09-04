//
//  RNIpSecVpn.swift
//  RNIpSecVpn
//
//  Created by Sina Javaheri on 25/02/1399.
//  Copyright © 1399 AP Sijav. All rights reserved.
//

import Foundation
import NetworkExtension
import Security



// Identifiers
let serviceIdentifier = "MySerivice"
let userAccount = "authenticatedUser"
let accessGroup = "MySerivice"

// Arguments for the keychain queries
var kSecAttrAccessGroupSwift = NSString(format: kSecClass)

let kSecClassValue = kSecClass as CFString
let kSecAttrAccountValue = kSecAttrAccount as CFString
let kSecValueDataValue = kSecValueData as CFString
let kSecClassGenericPasswordValue = kSecClassGenericPassword as CFString
let kSecAttrServiceValue = kSecAttrService as CFString
let kSecMatchLimitValue = kSecMatchLimit as CFString
let kSecReturnDataValue = kSecReturnData as CFString
let kSecMatchLimitOneValue = kSecMatchLimitOne as CFString
let kSecAttrGenericValue = kSecAttrGeneric as CFString
let kSecAttrAccessibleValue = kSecAttrAccessible as CFString

class KeychainService: NSObject {
    func save(key: String, value: String) {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let valueData: Data = value.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAlwaysThisDeviceOnly
        keychainQuery[kSecValueData as! NSCopying] = valueData
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }

    func load(key: String) -> Data {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAlwaysThisDeviceOnly
        keychainQuery[kSecMatchLimit] = kSecMatchLimitOne
        keychainQuery[kSecReturnPersistentRef] = kCFBooleanTrue

        var result: AnyObject?
        let status = withUnsafeMutablePointer(to: &result) { SecItemCopyMatching(keychainQuery, UnsafeMutablePointer($0)) }

        if status == errSecSuccess {
            if let data = result as! NSData? {
                if NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) != nil {}
                return data as Data
            }
        }
        return "".data(using: .utf8)!
    }

}

@objc(RNIpSecVpn)
class RNIpSecVpn: RCTEventEmitter {
    
    @objc override static func requiresMainQueueSetup() -> Bool {
        return true
    }

    override func supportedEvents() -> [String]! {
        return [ "stateChanged" ]
    }
    
    @objc
    func prepare(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {

        // Register to be notified of changes in the status. These notifications only work when app is in foreground.
        NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object : nil , queue: nil) {
            notification in let nevpnconn = notification.object as! NEVPNConnection
            self.sendEvent(withName: "stateChanged", body: [ "state" : checkNEStatus(status: nevpnconn.status) ])
        }
        findEventsWithResolver(nil)
    }
    
    @objc
    func connect(_ name: NSString, address: NSString, username: NSString, password: NSString, vpnType: NSString, secret: NSString, disconnectOnSleep: Bool, mtu: NSNumber, b64CaCert: NSString, b64UserCert: NSString, userCertPassword: NSString, certAlias: NSString, findEventsWithResolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) -> Void {
        let vpnManager = NEVPNManager.shared()
        let kcs = KeychainService()

        vpnManager.loadFromPreferences { (error) -> Void in

            if error != nil {
                print("VPN Preferences error: 1")
            } else {

                //vpnType == 'IKEv2' || vpnType == 'IPSec'
                if(vpnType == "IPSec") {
                    
                    let p = NEVPNProtocolIPSec()
                    p.username = username as String
                    p.serverAddress = address as String
                    p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret
                    
                    kcs.save(key: "secret", value: secret as String)
                    kcs.save(key: "password", value: password as String)
                    
                    p.sharedSecretReference = kcs.load(key: "secret")
                    p.passwordReference = kcs.load(key: "password")
                    
                    p.useExtendedAuthentication = true
                    p.disconnectOnSleep = disconnectOnSleep
                    
                    vpnManager.protocolConfiguration = p
                    
                } else {

let p = NEVPNProtocolIKEv2()

p.username = username as String
p.remoteIdentifier = address as String
p.serverAddress = address as String
//p.localIdentifier = "vpnclient"

p.childSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup.group14
p.childSecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm.algorithmAES128GCM
p.childSecurityAssociationParameters.lifetimeMinutes = 1410
p.ikeSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup.group14
p.ikeSecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithm.SHA256
p.ikeSecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm.algorithmAES256
p.ikeSecurityAssociationParameters.lifetimeMinutes = 1410

//p.disableMOBIKE = false
//p.disableRedirect = false
//p.enableRevocationCheck = false
//p.enablePFS = false
//p.useConfigurationAttributeInternalIPSubnet = false

//p.serverCertificateIssuerCommonName = "TEST SubCA"
//p.serverCertificateCommonName = "TEST SubCA"

p.authenticationMethod = NEVPNIKEAuthenticationMethod.certificate

//kcs.save(key: "secret", value: secret as String)
kcs.save(key: "password", value: password as String)
//kcs.save(key: "b64CaCert", value: b64CaCert as String)

//p.sharedSecretReference = kcs.load(key: "secret")
p.passwordReference = kcs.load(key: "password")
//p.certificateType = NEVPNIKEv2CertificateType.RSA

let pkcs12Cert = "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"

//let nnn = b64UserCert.replacingOccurrences(of: "\r\n", with: "")
//let certificateData = Data(base64Encoded: pkcs12Cert)
//, options: Data.Base64DecodingOptions(rawValue: 0)
//print("certificateData")
//print(certificateData ?? "nothing!")
//p.identityData = certificateData
//05c41851-5ea9-4166-b38a-a122ca3dc0c8
//p.identityDataPassword = secret as String
p.identityData = Data(base64Encoded: pkcs12Cert)
p.identityDataPassword = "GztrFW9pcGExwHPAGh"

print("ohoho")
print(p)

//p.useExtendedAuthentication = true
p.disconnectOnSleep = disconnectOnSleep

vpnManager.protocolConfiguration = p
                }
                

                vpnManager.isEnabled = true
                
                let defaultErr = NSError()

                vpnManager.saveToPreferences(completionHandler: { (error) -> Void in
                    if error != nil {
                        print("VPN Preferences error: 2")
                        rejecter("VPN_ERR", "VPN Preferences error: 2", defaultErr)
                    } else {
                        vpnManager.loadFromPreferences(completionHandler: { error in

                            if error != nil {
                                print("VPN Preferences error: 2")
                                rejecter("VPN_ERR", "VPN Preferences error: 2", defaultErr)
                            } else {
                                var startError: NSError?

                                do {
                                    try vpnManager.connection.startVPNTunnel()
                                } catch let error as NSError {
                                    startError = error
                                    print(startError ?? "VPN Manager cannot start tunnel")
                                    rejecter("VPN_ERR", "VPN Manager cannot start tunnel", startError)
                                } catch {
                                    print("Fatal Error")
                                    rejecter("VPN_ERR", "Fatal Error", NSError(domain: "", code: 200, userInfo: nil))
                                    fatalError()
                                }
                                if startError != nil {
                                    print("VPN Preferences error: 3")
                                    print(startError ?? "Start Error")
                                    //rejecter("VPN_ERR", "VPN Preferences error: 3", startError)
                                } else {
                                    print("VPN started successfully..")
                                    findEventsWithResolver(nil)
                                }
                            }
                        })
                    }
                })
            }
        }
        
    }
    
    @objc
    func disconnect(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        let vpnManager = NEVPNManager.shared()
        vpnManager.connection.stopVPNTunnel()
        findEventsWithResolver(nil)
    }
    
    @objc
    func getCurrentState(_ findEventsWithResolver:RCTPromiseResolveBlock, rejecter:RCTPromiseRejectBlock) -> Void {
        let vpnManager = NEVPNManager.shared()
        let status = checkNEStatus(status: vpnManager.connection.status)
        if(status.intValue < 5){
            findEventsWithResolver(status)
        } else {
            rejecter("VPN_ERR", "Unknown state", NSError())
            fatalError()
        }
    }
    
    @objc
    func getCharonErrorState(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        findEventsWithResolver(nil)
    }

}


func checkNEStatus( status:NEVPNStatus ) -> NSNumber {
    switch status {
    case .connecting:
        return 1
    case .connected:
        return 2
    case .disconnecting:
        return 3
    case .disconnected:
        return 0
    case .invalid:
        return 0
    case .reasserting:
        return 4
    @unknown default:
        return 5
    }
}
