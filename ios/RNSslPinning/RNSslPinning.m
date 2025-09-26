//
//  Created by Max Toyberman on 13/10/16.

#import "RNSslPinning.h"
#import "AFNetworking.h"

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


-(void)performRequest:(AFURLSessionManager*)manager  obj:(NSDictionary *)obj  request:(NSMutableURLRequest*) request callback:(RCTResponseSenderBlock) callback  {
#if DEBUG
    if (_requestObserver) {
        _requestObserver(request);
    }
#endif

    NSURLRequest *capturedRequest = [request copy]; // 🧠 Save the original request - for interceptors purposes
    NSTimeInterval startTime = [[NSDate date] timeIntervalSince1970] * 1000.0;


    [[manager dataTaskWithRequest:request uploadProgress:nil downloadProgress:nil completionHandler:^(NSURLResponse * _Nonnull response, id _Nullable responseObject, NSError * _Nullable error) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
        NSString *bodyString = [[NSString alloc] initWithData: responseObject encoding:NSUTF8StringEncoding];
        NSInteger statusCode = httpResp.statusCode;
        
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
    
    NSSet *certificates = [AFSecurityPolicy certificatesInBundle:[NSBundle mainBundle]];
    
    // Debug logging: enumerate bundled .cer files and policy inputs
    NSArray<NSString *> *cerPaths = [[NSBundle mainBundle] pathsForResourcesOfType:@"cer" inDirectory:nil];
    NSLog(@"[RNSslPinning] Found %lu .cer file(s) in main bundle", (unsigned long)cerPaths.count);
    for (NSString *path in cerPaths) {
        NSLog(@"[RNSslPinning] .cer in bundle: %@", [path lastPathComponent]);
    }
    NSLog(@"[RNSslPinning] certificatesInBundle count=%lu, pkPinning=%@, disableAllSecurity=%@",
          (unsigned long)[certificates count],
          pkPinning ? @"YES" : @"NO",
          disableAllSecurity ? @"YES" : @"NO");
    
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
    policy.validatesDomainName = false;

    NSLog(@"[RNSslPinning] Final policy flags -> validatesDomainName=%@, allowInvalidCertificates=%@",
          policy.validatesDomainName ? @"YES" : @"NO",
          policy.allowInvalidCertificates ? @"YES" : @"NO");
    manager.securityPolicy = policy;
    
    // Skip hostname validation by evaluating server trust with domain=nil while still enforcing pinning
    manager.sessionDidReceiveAuthenticationChallenge = ^NSURLSessionAuthChallengeDisposition(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential *__autoreleasing *credential) {
        if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
            NSString *domain = nil; // Passing nil to avoid hostname validation
            BOOL trusted = [policy evaluateServerTrust:serverTrust forDomain:domain];
            NSLog(@"[RNSslPinning] evaluateServerTrust(forDomain:nil) => %@", trusted ? @"YES" : @"NO");
            if (trusted) {
                *credential = [NSURLCredential credentialForTrust:serverTrust];
                return NSURLSessionAuthChallengeUseCredential;
            }
            return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
        }
        NSLog(@"[RNSslPinning] [session] performDefaultHandling");
        return NSURLSessionAuthChallengePerformDefaultHandling;
    };

    // Ensure task-level challenges also route through our evaluation (often preferred by NSURLSession)
    manager.taskDidReceiveAuthenticationChallenge = ^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLSessionTask * _Nonnull task, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
            NSString *domain = nil;
            BOOL trusted = [policy evaluateServerTrust:serverTrust forDomain:domain];
            NSLog(@"[RNSslPinning] [task] evaluateServerTrust(forDomain:nil) => %@", trusted ? @"YES" : @"NO");
            if (trusted) {
                *credential = [NSURLCredential credentialForTrust:serverTrust];
                return NSURLSessionAuthChallengeUseCredential;
            }
            return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
        }
        NSLog(@"[RNSslPinning] [task] performDefaultHandling");
        return NSURLSessionAuthChallengePerformDefaultHandling;
    };
    
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
