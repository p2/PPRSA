//
//  PPRSA.h
//  medcalc-3
//
//  Created by Pascal Pfiffner on 8/22/15.
//

#import <Foundation/Foundation.h>


extern NSString * const PPRSAErrorDomain;


/**
 *  Simple class for RSA en- and decryption.
 */
@interface PPRSA : NSObject

#pragma mark Encryption

/**
 *  Loads the public key from a bundled X509 certificate.
 */
- (BOOL)loadPublicKeyFromBundledCertificate:(NSString *)name error:(NSError **)error;

/**
 *  Encrypts given data with the public key.
 */
- (NSData *)encryptData:(NSData *)plainData error:(NSError **)error;


#pragma mark Decryption

/**
 *  Loads the private key from given NSData. This is preferable over storing the actual .p12 file in the app bundle!
 */
- (BOOL)loadPrivateKeyFromP12Data:(NSData *)certData password:(NSString *)password error:(NSError **)error;

/**
 *  Loads the private key with the given password. Can easily be extracted from your app, so use wisely!
 */
- (BOOL)loadPrivateKeyFromBundledP12:(NSString *)name password:(NSString *)password error:(NSError **)error;

/**
 *  Decrypts given data with the private key.
 */
- (NSData *)decryptData:(NSData *)encData error:(NSError **)error;


#pragma mark Utilities

/**
 *  Utility function to create a random string of a given length. Contains alphanumeric letters as well as "@%#$^_.*-+/=".
 */
+ (NSString *)randomStringOfLength:(NSUInteger)length;

@end
