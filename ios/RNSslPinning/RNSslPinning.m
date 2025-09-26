//
//  Created by Max Toyberman on 13/10/16.

#import "RNSslPinning.h"
#import "AFNetworking.h"
// + COMMIT: Add Security framework import for detailed certificate logging
#import <Security/Security.h>
// + COMMIT: Add CommonCrypto for certificate hash calculation
#import <CommonCrypto/CommonDigest.h>

static void (^_requestObserver)(NSURLRequest *) = nil;
static void (^_responseObserver)(NSURLRequest *, NSHTTPURLResponse *, NSData *, NSTimeInterval) = nil;

@interface RNSslPinning()

@property (nonatomic, strong) NSURLSessionConfiguration *sessionConfig;

@end

@implementation RNSslPinning
RCT_EXPORT_MODULE();

+ (void)setRequestObserver:(void (^)(NSURLRequest *))observer {
#if DEBUG
  _requestObserver = [observer copy];
#endif
}

+ (void)setResponseObserver:(void (^)(NSURLRequest *, NSHTTPURLResponse *, NSData *, NSTimeInterval))observer {
#if DEBUG
  _responseObserver = [observer copy];
#endif
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        self.sessionConfig.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    }
    return self;
}

RCT_EXPORT_METHOD(getCookies: (NSURL *)url resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    
    NSHTTPCookie *cookie;
    NSHTTPCookieStorage* cookieJar  =  NSHTTPCookieStorage.sharedHTTPCookieStorage;
    
    NSMutableDictionary* dictionary = @{}.mutableCopy;
    
    for (cookie in [cookieJar cookiesForURL:url]) {
        [dictionary setObject:cookie.value forKey:cookie.name];
    }
    
    if ([dictionary count] > 0){
        resolve(dictionary);
    }
    else{
        NSError *error = nil;
        reject(@"no_cookies", @"There were no cookies", error);
    }
}

RCT_EXPORT_METHOD(removeCookieByName: (NSString *)cookieName
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    
    NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *cookie in cookieStorage.cookies) {
        // [cookieStorage deleteCookie:each];
        NSString * name = cookie.name;
        
        if([cookieName isEqualToString:name]) {
            [cookieStorage deleteCookie:cookie];
        }
    }
    
    resolve(nil);
    
}

// + COMMIT: Add new method for detailed certificate validation logging
- (void)logCertificateDetails:(SecCertificateRef)certificate withTitle:(NSString *)title {
    if (!certificate) {
        NSLog(@"[RNSslPinning] %@ is NULL", title);
        return;
    }
    
    // Get certificate subject
    CFStringRef subject = SecCertificateCopySubjectSummary(certificate);
    NSLog(@"[RNSslPinning] %@ Subject: %@", title, subject ?: @"Unknown");
    if (subject) CFRelease(subject);
    
    // Calculate certificate SHA256 hash for comparison
    CFDataRef certData = SecCertificateCopyData(certificate);
    if (certData) {
        NSData *data = (__bridge NSData *)certData;
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
        
        NSMutableString *hashString = [NSMutableString string];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            [hashString appendFormat:@"%02x", hash[i]];
        }
        
        NSLog(@"[RNSslPinning] %@ SHA256: %@", title, hashString);
        CFRelease(certData);
    }
}

// + COMMIT: Add method to log server certificate chain details
- (void)logServerTrustDetails:(SecTrustRef)serverTrust {
    if (!serverTrust) {
        NSLog(@"[RNSslPinning] Server trust is NULL");
        return;
    }
    
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    NSLog(@"[RNSslPinning] Server certificate chain contains %ld certificate(s)", certCount);
    
    for (CFIndex i = 0; i < certCount; i++) {
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, i);
        [self logCertificateDetails:cert withTitle:[NSString stringWithFormat:@"Server Cert[%ld]", i]];
    }
}

// + COMMIT: Add method to log trust evaluation result details
- (void)logTrustEvaluationResult:(SecTrustResultType)result status:(OSStatus)status {
    NSLog(@"[RNSslPinning] Trust evaluation OSStatus: %d", (int)status);
    
    NSString *resultString;
    switch (result) {
        case kSecTrustResultInvalid:
            resultString = @"Invalid";
            break;
        case kSecTrustResultProceed:
            resultString = @"Proceed (user approved)";
            break;
        case kSecTrustResultDeny:
            resultString = @"Deny (user rejected)";
            break;
        case kSecTrustResultUnspecified:
            resultString = @"Unspecified (system trusts)";
            break;
        case kSecTrustResultRecoverableTrustFailure:
            resultString = @"Recoverable Trust Failure";
            break;
        case kSecTrustResultFatalTrustFailure:
            resultString = @"Fatal Trust Failure";
            break;
        case kSecTrustResultOtherError:
            resultString = @"Other Error";
            break;
        default:
            resultString = [NSString stringWithFormat:@"Unknown (%u)", result];
            break;
    }
    
    NSLog(@"[RNSslPinning] Trust result: %@", resultString);
    
    if (result == kSecTrustResultRecoverableTrustFailure || result == kSecTrustResultFatalTrustFailure) {
        NSLog(@"[RNSslPinning] ❌ Certificate validation FAILED");
    } else if (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed) {
        NSLog(@"[RNSslPinning] ✅ Certificate validation PASSED");
    }
}

// + COMMIT: Add new method to test certificate loading and validation
RCT_EXPORT_METHOD(debugCertificateInfo:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    
    NSMutableArray *certInfo = [[NSMutableArray alloc] init];
    
    // Check for .cer files in bundle
    NSArray<NSString *> *cerPaths = [[NSBundle mainBundle] pathsForResourcesOfType:@"cer" inDirectory:nil];
    NSArray<NSString *> *crtPaths = [[NSBundle mainBundle] pathsForResourcesOfType:@"crt" inDirectory:nil];
    
    NSLog(@"[RNSslPinning] Found %lu .cer files and %lu .crt files in bundle", 
          (unsigned long)cerPaths.count, (unsigned long)crtPaths.count);
    
    // Process .cer files
    for (NSString *path in cerPaths) {
        NSString *filename = [[path lastPathComponent] stringByDeletingPathExtension];
        NSData *certData = [NSData dataWithContentsOfFile:path];
        
        if (certData) {
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
            if (cert) {
                CFStringRef subject = SecCertificateCopySubjectSummary(cert);
                
                [certInfo addObject:@{
                    @"filename": filename,
                    @"type": @"cer",
                    @"size": @(certData.length),
                    @"subject": (__bridge NSString *)subject ?: @"Unknown",
                    @"valid": @YES
                }];
                
                [self logCertificateDetails:cert withTitle:[NSString stringWithFormat:@"Bundle Cert: %@", filename]];
                
                if (subject) CFRelease(subject);
                CFRelease(cert);
            } else {
                [certInfo addObject:@{
                    @"filename": filename,
                    @"type": @"cer",
                    @"size": @(certData.length),
                    @"error": @"Invalid certificate format",
                    @"valid": @NO
                }];
            }
        }
    }
    
    // Process .crt files
    for (NSString *path in crtPaths) {
        NSString *filename = [[path lastPathComponent] stringByDeletingPathExtension];
        NSData *certData = [NSData dataWithContentsOfFile:path];
        
        if (certData) {
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
            if (cert) {
                CFStringRef subject = SecCertificateCopySubjectSummary(cert);
                
                [certInfo addObject:@{
                    @"filename": filename,
                    @"type": @"crt",
                    @"size": @(certData.length),
                    @"subject": (__bridge NSString *)subject ?: @"Unknown",
                    @"valid": @YES
                }];
                
                [self logCertificateDetails:cert withTitle:[NSString stringWithFormat:@"Bundle Cert: %@", filename]];
                
                if (subject) CFRelease(subject);
                CFRelease(cert);
            } else {
                [certInfo addObject:@{
                    @"filename": filename,
                    @"type": @"crt", 
                    @"size": @(certData.length),
                    @"error": @"Invalid certificate format",
                    @"valid": @NO
                }];
            }
        }
    }
    
    resolve(@{
        @"certificates": certInfo,
        @"cerCount": @(cerPaths.count),
        @"crtCount": @(crtPaths.count)
    });
}

-(void)performRequest:(AFURLSessionManager*)manager  obj:(NSDictionary *)obj  request:(NSMutableURLRequest*) request callback:(RCTResponseSenderBlock) callback  {
#if DEBUG
    if (_requestObserver) {
        _requestObserver(request);
    }
#endif

    NSURLRequest *capturedRequest = [request copy]; // 🧠 Save the original request - for interceptors purposes
    NSTimeInterval startTime = [[NSDate date] timeIntervalSince1970] * 1000.0;

    // + COMMIT: Add detailed request logging
    NSLog(@"[RNSslPinning] 🚀 Starting request to: %@", request.URL);
    NSLog(@"[RNSslPinning] Request method: %@", request.HTTPMethod);
    NSLog(@"[RNSslPinning] Request headers: %@", request.allHTTPHeaderFields);

    [[manager dataTaskWithRequest:request uploadProgress:nil downloadProgress:nil completionHandler:^(NSURLResponse * _Nonnull response, id _Nullable responseObject, NSError * _Nullable error) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
        NSString *bodyString = [[NSString alloc] initWithData: responseObject encoding:NSUTF8StringEncoding];
        NSInteger statusCode = httpResp.statusCode;
        
        // + COMMIT: Add detailed response/error logging
        NSTimeInterval duration = ([[NSDate date] timeIntervalSince1970] * 1000.0) - startTime;
        
        if (error) {
            NSLog(@"[RNSslPinning] ❌ Request failed after %.0fms with error: %@", duration, error.localizedDescription);
            NSLog(@"[RNSslPinning] Error domain: %@, code: %ld", error.domain, (long)error.code);
            NSLog(@"[RNSslPinning] Error userInfo: %@", error.userInfo);
            
            // Check for specific SSL errors
            if ([error.domain isEqualToString:NSURLErrorDomain]) {
                switch (error.code) {
                    case NSURLErrorServerCertificateUntrusted:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error: Server certificate untrusted");
                        break;
                    case NSURLErrorServerCertificateHasBadDate:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error: Certificate has bad date");
                        break;
                    case NSURLErrorServerCertificateHasUnknownRoot:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error: Certificate has unknown root");
                        break;
                    case NSURLErrorServerCertificateNotYetValid:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error: Certificate not yet valid");
                        break;
                    case NSURLErrorClientCertificateRejected:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error: Client certificate rejected");
                        break;
                    default:
                        NSLog(@"[RNSslPinning] 🔒 SSL Error code: %ld", (long)error.code);
                        break;
                }
            }
        } else {
            NSLog(@"[RNSslPinning] ✅ Request completed after %.0fms with status: %ld", duration, (long)statusCode);
        }
        
        // Don't create a synthetic response - pass the real one to observer along with error
        if (error && (!httpResp || httpResp.statusCode == 0)) {
            bodyString = error.localizedDescription;
        }

#if DEBUG
        if (_responseObserver) {
            NSData *rawData = nil;
            if (responseObject) {
                rawData = [responseObject isKindOfClass:[NSData class]]
                    ? responseObject
                    : [NSJSONSerialization dataWithJSONObject:responseObject options:0 error:nil];
            } else if (error) {
                // Create error response data if we have an error but no response data
                NSString *errorMessage = error.localizedDescription ?: @"Unknown error";
                rawData = [errorMessage dataUsingEncoding:NSUTF8StringEncoding];
            }
            
            // Pass the raw error to our observer with the start time
            _responseObserver(capturedRequest, httpResp, rawData ?: [NSData new], startTime);
        }
#endif

        if (!error) {
            // if(obj[@"responseType"]){
            NSString * responseType = obj[@"responseType"];
            
            if ([responseType isEqualToString:@"base64"]){
                NSString* base64String = [responseObject base64EncodedStringWithOptions:0];
                callback(@[[NSNull null], @{
                               @"status": @(statusCode),
                               @"headers": httpResp.allHeaderFields,
                               @"data": base64String
                }]);
            }
            else {
                callback(@[[NSNull null], @{
                               @"status": @(statusCode),
                               @"headers": httpResp.allHeaderFields,
                               @"bodyString": bodyString ? bodyString : @""
                }]);
            }
        } else if (error && error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{
                               @"status": @(statusCode),
                               @"headers": httpResp.allHeaderFields,
                               @"bodyString": bodyString ? bodyString : @""
                }, [NSNull null]]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[error.localizedDescription, [NSNull null]]);
            });
        }
    }] resume];
    
}


-(void) setHeaders: (NSDictionary *)obj request:(NSMutableURLRequest*) request {
    
    if (obj[@"headers"] && [obj[@"headers"] isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *m = [obj[@"headers"] mutableCopy];
        for (NSString *key in [m allKeys]) {
            if (![m[key] isKindOfClass:[NSString class]]) {
                m[key] = [m[key] stringValue];
            }
        }
        [request setAllHTTPHeaderFields:m];
    }
    
}

- (BOOL) isFilePart: (NSArray*)part {
    if (![part[1] isKindOfClass:[NSDictionary class]]) {
        return NO;
    }
    NSDictionary * value = part[1];
    return [value objectForKey:@"type"] && ([value objectForKey:@"name"] || [value objectForKey:@"fileName"]);
}

-(void) appendFormDataFilePart: (id<AFMultipartFormData>) formData fileData: (NSArray*) fileData  {
    NSString * key = fileData[0];
    NSDictionary * value = fileData[1];
    NSString * fileName = [value objectForKey:@"name"] ? [value objectForKey:@"name"] : [value objectForKey:@"fileName"];
    NSString * mimeType = [value objectForKey:@"type"];
    NSString * path = [value objectForKey:@"uri"] ? [value objectForKey:@"uri"] : [value objectForKey:@"path"];
    
    [formData appendPartWithFileURL:[NSURL URLWithString:path] name:key fileName:fileName mimeType:mimeType error:nil];
}

-(void) performMultipartRequest: (AFURLSessionManager*)manager obj:(NSDictionary *)obj url:(NSString *)url request:(NSMutableURLRequest*) request callback:(RCTResponseSenderBlock) callback formData:(NSDictionary*) formData {
    NSString * method = obj[@"method"] ? obj[@"method"] : @"POST";
    
    NSMutableURLRequest *formDataRequest = [[AFHTTPRequestSerializer serializer] multipartFormRequestWithMethod:method URLString:url parameters:nil constructingBodyWithBlock:^(id<AFMultipartFormData> _formData) {
        if([formData objectForKey:@"_parts"]){
            NSArray * parts = formData[@"_parts"];
            for (int i = 0; i < [parts count]; i++)
            {
                NSArray * part = parts[i];
                NSString * key = part[0];
                
                if ([self isFilePart:part]) {
                    [self appendFormDataFilePart:_formData fileData: part];
                } else {
                    NSString * value = part[1];
                    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
                    [_formData appendPartWithFormData:data name: key];
                }
            }
        }
    } error:nil];
    
    // Migrate header fields.
    [formDataRequest setAllHTTPHeaderFields:[request allHTTPHeaderFields]];
    
    NSURLSessionUploadTask *uploadTask = [manager
                                          uploadTaskWithStreamedRequest:formDataRequest
                                          progress:^(NSProgress * _Nonnull uploadProgress) {
        NSLog(@"Upload progress %lld", uploadProgress.completedUnitCount / uploadProgress.totalUnitCount);
    }
                                          completionHandler:^(NSURLResponse * _Nonnull response, id  _Nullable responseObject, NSError * _Nullable error) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
        NSString *bodyString = [[NSString alloc] initWithData: responseObject encoding:NSUTF8StringEncoding];
        NSInteger statusCode = httpResp.statusCode;
        if (!error) {
            
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
            
            NSString *bodyString = [[NSString alloc] initWithData: responseObject encoding:NSUTF8StringEncoding];
            NSInteger statusCode = httpResp.statusCode;
            
            NSDictionary *res = @{
                @"status": @(statusCode),
                @"headers": httpResp.allHeaderFields,
                @"bodyString": bodyString ? bodyString : @""
            };
            callback(@[[NSNull null], res]);
        }
        else if (error && error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{
                               @"status": @(statusCode),
                               @"headers": httpResp.allHeaderFields,
                               @"bodyString": bodyString ? bodyString : @""
                }, [NSNull null]]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[error.localizedDescription, [NSNull null]]);
            });
        }
    }];
    
    [uploadTask resume];
}

RCT_EXPORT_METHOD(fetch:(NSString *)url obj:(NSDictionary *)obj callback:(RCTResponseSenderBlock)callback) {
    NSURL *u = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:u];
    
    AFSecurityPolicy *policy;
    BOOL pkPinning = [[obj objectForKey:@"pkPinning"] boolValue];
    BOOL disableAllSecurity = [[obj objectForKey:@"disableAllSecurity"] boolValue];
    BOOL skipHostnameVerification = [[obj objectForKey:@"skipHostnameVerification"] boolValue];
    
    NSSet *certificates = [AFSecurityPolicy certificatesInBundle:[NSBundle mainBundle]];
    
    // Debug logging: enumerate bundled .cer files and policy inputs
    NSArray<NSString *> *cerPaths = [[NSBundle mainBundle] pathsForResourcesOfType:@"cer" inDirectory:nil];
    // + COMMIT: Also check for .crt files
    NSArray<NSString *> *crtPaths = [[NSBundle mainBundle] pathsForResourcesOfType:@"crt" inDirectory:nil];
    NSLog(@"[RNSslPinning] Found %lu .cer file(s) and %lu .crt file(s) in main bundle", 
          (unsigned long)cerPaths.count, (unsigned long)crtPaths.count);
    
    for (NSString *path in cerPaths) {
        NSLog(@"[RNSslPinning] .cer in bundle: %@", [path lastPathComponent]);
    }
    // + COMMIT: Log .crt files as well
    for (NSString *path in crtPaths) {
        NSLog(@"[RNSslPinning] .crt in bundle: %@", [path lastPathComponent]);
    }
    
    NSLog(@"[RNSslPinning] certificatesInBundle count=%lu, pkPinning=%@, disableAllSecurity=%@, skipHostnameVerification=%@",
          (unsigned long)[certificates count],
          pkPinning ? @"YES" : @"NO",
          disableAllSecurity ? @"YES" : @"NO",
          skipHostnameVerification ? @"YES" : @"NO");
    
    // + COMMIT: Log individual certificate details from bundle
    for (NSData *certData in certificates) {
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
        if (cert) {
            [self logCertificateDetails:cert withTitle:@"Pinned Certificate"];
            CFRelease(cert);
        }
    }
    
    // set policy (ssl pinning)
    if(disableAllSecurity){
        policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
        policy.allowInvalidCertificates = true;
        NSLog(@"[RNSslPinning] Using pinning mode: None (all security disabled)");
    }
    else if (pkPinning){
        policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey withPinnedCertificates:certificates];
        NSLog(@"[RNSslPinning] Using pinning mode: PublicKey, pinned certs: %lu", (unsigned long)[certificates count]);
    }
    else{
        policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate withPinnedCertificates:certificates];
        NSLog(@"[RNSslPinning] Using pinning mode: Certificate, pinned certs: %lu", (unsigned long)[certificates count]);
    }
    
    AFURLSessionManager *manager = [[AFURLSessionManager alloc] initWithSessionConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    policy.validatesDomainName = !skipHostnameVerification;

    NSLog(@"[RNSslPinning] Final policy flags -> validatesDomainName=%@, allowInvalidCertificates=%@",
          policy.validatesDomainName ? @"YES" : @"NO",
          policy.allowInvalidCertificates ? @"YES" : @"NO");
    
    // + COMMIT: Add custom security policy evaluation with detailed logging
    if (!disableAllSecurity) {
        AFSecurityPolicy *originalPolicy = policy;
        policy = [AFSecurityPolicy policyWithPinningMode:originalPolicy.SSLPinningMode withPinnedCertificates:originalPolicy.pinnedCertificates];
        policy.allowInvalidCertificates = originalPolicy.allowInvalidCertificates;
        policy.validatesDomainName = originalPolicy.validatesDomainName;
        
        // Override the evaluation method to add logging
        policy.serverTrustEvaluator = ^BOOL(SecTrustRef serverTrust, NSString *domain) {
            NSLog(@"[RNSslPinning] 🔐 Evaluating server trust for domain: %@", domain);
            
            // Log server certificate details
            [self logServerTrustDetails:serverTrust];
            
            // Perform the original evaluation
            BOOL result = [originalPolicy evaluateServerTrust:serverTrust forDomain:domain];
            
            NSLog(@"[RNSslPinning] Server trust evaluation result: %@", result ? @"✅ PASSED" : @"❌ FAILED");
            
            if (!result) {
                // Get additional failure details
                SecTrustResultType trustResult;
                OSStatus status = SecTrustEvaluate(serverTrust, &trustResult);
                [self logTrustEvaluationResult:trustResult status:status];
                
                // Log trust properties for debugging
                CFArrayRef properties = SecTrustCopyProperties(serverTrust);
                if (properties) {
                    NSArray *propsArray = (__bridge NSArray *)properties;
                    NSLog(@"[RNSslPinning] Trust failure properties: %@", propsArray);
                    CFRelease(properties);
                }
            }
            
            return result;
        };
    }
    
    manager.securityPolicy = policy;
    
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    
    
    if (obj[@"method"]) {
        [request setHTTPMethod:obj[@"method"]];
    }
    if (obj[@"timeoutInterval"]) {
        [request setTimeoutInterval:[obj[@"timeoutInterval"] doubleValue] / 1000];
    }
    
    if(obj[@"headers"]) {
        [self setHeaders:obj request:request];
    }
    
    if (obj) {
        
        if ([obj objectForKey:@"body"]) {
            NSDictionary * body = obj[@"body"];
            
            // this is a multipart form data request
            if([body isKindOfClass:[NSDictionary class]]){
                // post multipart
                if ([body objectForKey:@"formData"]) {
                    [self performMultipartRequest:manager obj:obj url:url request:request callback:callback formData:body[@"formData"]];
                } else if ([body objectForKey:@"_parts"]) {
                    [self performMultipartRequest:manager obj:obj url:url request:request callback:callback formData:body];
                }
            }
            else {
                
                // post a string
                NSData *data = [obj[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
                [request setHTTPBody:data];
                [self performRequest:manager obj:obj request:request callback:callback ];
                //TODO: if no body
            }
            
        }
        else {
            [self performRequest:manager obj:obj request:request callback:callback ];
        }
    }
    else {
        
    }
    
}

+ (BOOL)requiresMainQueueSetup
{
    return YES;
}

@end