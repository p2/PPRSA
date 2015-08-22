//
//  PPRSA.m
//  medcalc-3
//
//  Created by Pascal Pfiffner on 8/22/15.
//

#import "PPRSA.h"


NSString * const PPRSAErrorDomain = @"PPRSAErrorDomain";

const uint32_t PPRSA_PADDING = kSecPaddingPKCS1;


@interface PPRSA () {
	SecKeyRef publicKey;
	SecKeyRef privateKey;
}

@end


@implementation PPRSA


#pragma mark - Key Loading

- (BOOL)loadPublicKeyFromBundledCertificate:(NSString *)name error:(NSError **)error
{
	NSURL *url = [[NSBundle mainBundle] URLForResource:name withExtension:@"crt"];
	if (url) {
		NSData *certData = [NSData dataWithContentsOfURL:url];
		if (certData) {
			SecKeyRef public = [self loadPublicKey:certData error:error];
			if (public) {
				if (publicKey) {
					CFRelease(publicKey);
				}
				publicKey = public;
				return YES;
			}
		}
		else if (error) {
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read bundled public key data"}];
		}
	}
	else if (error) {
		NSString *message = [NSString stringWithFormat:@"Bundled certificate named «%@.crt» not found", name];
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
	}
	return NO;
}

- (SecKeyRef)loadPublicKey:(NSData *)data error:(NSError **)error
{
	SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)data);
	if (certificate) {
		SecPolicyRef policy = SecPolicyCreateBasicX509();
		SecTrustRef trust;
		OSStatus status = SecTrustCreateWithCertificates(certificate, policy, &trust);
		if (errSecSuccess == status) {
			return SecTrustCopyPublicKey(trust);
		}
		if (error) {
			NSString *message = [NSString stringWithFormat:@"Failed to establish trust with certificate: %d", (int)status];
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
		}
	}
	else if (error) {
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Failed to create certificate"}];
	}
	return NULL;
}


- (BOOL)loadPrivateKeyFromBundledP12:(NSString *)name password:(NSString *)password error:(NSError **)error
{
	NSURL *url = [[NSBundle mainBundle] URLForResource:name withExtension:@"p12"];
	if (url) {
		NSData *certData = [NSData dataWithContentsOfURL:url];
		if (certData) {
			return [self loadPrivateKeyFromP12Data:certData password:password error:error];
		}
		else if (error) {
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read bundled private key data"}];
		}
	}
	else if (error) {
		NSString *message = [NSString stringWithFormat:@"Bundled private key file named «%@.p12» not found", name];
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
	}
	return NO;
}

- (BOOL)loadPrivateKeyFromP12Data:(NSData *)certData password:(NSString *)password error:(NSError **)error
{
	NSParameterAssert(certData);
	NSLog(@"PRIVATE Base62:  %@", [certData base64EncodedStringWithOptions:0]);
	
	SecKeyRef private = [self loadPrivateKey:certData withPassword:password error:error];
	if (private) {
		if (privateKey) {
			CFRelease(privateKey);
		}
		privateKey = private;
		return YES;
	}
	return NO;
}

- (SecKeyRef)loadPrivateKey:(NSData *)keyData withPassword:(NSString *)password error:(NSError **)error
{
	SecKeyRef privateKeyRef = NULL;
	NSDictionary *options = @{(__bridge id)kSecImportExportPassphrase: password};
	CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
	
	OSStatus status = SecPKCS12Import((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)options, &items);
	if (status == noErr && CFArrayGetCount(items) > 0) {
		CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
		SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
		
		status = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
		if (status != noErr) {
			privateKeyRef = NULL;
			if (error) {
				NSString *message = [NSString stringWithFormat:@"Failed to copy private key data, error code: %d", (int)status];
				*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
			}
		}
	}
	else if (error) {
		NSString *message = [self messageForP12ImportErrorCode:status];
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
	}
	CFRelease(items);
	return privateKeyRef;
}



#pragma mark - Encryption

- (NSData *)encryptData:(NSData *)plainData error:(NSError **)error
{
	if (NULL == publicKey) {
		if (error) {
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No public key has been loaded, cannot encrypt"}];
		}
		return nil;
	}
	
	SecKeyRef key = publicKey;
	size_t cipherBufferSize = SecKeyGetBlockSize(key);
	size_t maxSize = cipherBufferSize - 11;				// valid for PKCS1 padding only!
	if (maxSize < plainData.length) {
		if (error) {
			NSString *message = [NSString stringWithFormat:@"Too much data, cannot encrypt. Max %lu byte, have %lu", (unsigned long)maxSize, (unsigned long)plainData.length];
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
		}
		return nil;
	}
	
	NSMutableData *buffer = [NSMutableData dataWithLength:cipherBufferSize];
	uint8_t *cipherBufferPointer = buffer.mutableBytes;
	size_t cipherBufferResultSize = cipherBufferSize;
	
	// encrypt data
	OSStatus status = SecKeyEncrypt(key, PPRSA_PADDING, plainData.bytes, plainData.length, cipherBufferPointer, &cipherBufferResultSize);
	if (noErr == status) {
		return [buffer copy];
	}
	if (error) {
		NSString *message = [NSString stringWithFormat:@"Failed to encrypt data, error code: %d", (int)status];
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
	}
	return nil;
}

- (NSData *)decryptData:(NSData *)encData error:(NSError **)error
{
	if (NULL == privateKey) {
		if (error) {
			*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"No private key has been loaded, cannot decrypt"}];
		}
		return nil;
	}
	
	SecKeyRef key = privateKey;
	size_t plainBufferSize = SecKeyGetBlockSize(key);
	NSMutableData *buffer = [NSMutableData dataWithLength:plainBufferSize];
	uint8_t *plainBufferPointer = buffer.mutableBytes;
	size_t plainBufferResultSize = plainBufferSize;
	
	// decrypt data
	OSStatus status = SecKeyDecrypt(key, PPRSA_PADDING, encData.bytes, encData.length, plainBufferPointer, &plainBufferResultSize);
	if (noErr == status) {
		return [buffer copy];
	}
	if (error) {
		NSString *message = [NSString stringWithFormat:@"Failed to decrypt data, error code: %d", (int)status];
		*error = [NSError errorWithDomain:PPRSAErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: message}];
	}
	return nil;
}



#pragma mark - Utilities

- (NSString *)messageForP12ImportErrorCode:(OSStatus)code
{
	switch (code) {
		case errSecAuthFailed:
			return @"Failed to import P12 data: wrong password";
		default:
			return [NSString stringWithFormat:@"Failed to import P12 data, error code: %d", (int)code];
	}
}


@end
