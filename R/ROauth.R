setAs("OAuth", "OAuthCredentials",
          function(from) {
            new("OAuthCredentials",
                 consumerKey = from$consumerKey,
                 consumerSecret = from$consumerSecret,
                 oauthKey = from$oauthKey,
                 oauthSecret = from$oauthSecret,
                 signMethod = from$signMethod,
                 authURL = from$authURL,
                 accessURL = from$accessURL,
                 requestURL = from$requestURL
               )
          })


oauth =
function(consumerKey, consumerSecret,
         requestURL, authURL, accessURL,
         signMethod = 'HMAC',
         obj = new("OAuthCredentials"))
{
  obj@consumerKey = consumerKey
  obj@consumerSecret = consumerSecret
  obj@requestURL = requestURL
  obj@authURL = authURL
  obj@accessURL = accessURL
  obj@signMethod = signMethod

  obj
}

handshake = authorize =
function(cred, post = TRUE,
         signMethod = 'HMAC', curl = getCurlHandle(),
         verify = TRUE, ...
        )
{
  if(!is(cred, "OAuthCredentials"))
      cred = as(cred, "OAuthCredentials")
  
  op = if(post) oauthPOST else oauthGET
                
  resp <- op(cred@requestURL, cred@consumerKey, cred@consumerSecret,
             NULL, NULL, signMethod = cred@signMethod, curl = curl,
             handshakeComplete = FALSE, ...) # , callback = "oob")
  vals <- parseResponse(resp)
  if (!all(c('oauth_token', 'oauth_token_secret') %in%
           names(vals))) {
    stop("Invalid response from site, please ",
         "check your consumerKey and consumerSecret",
         " and try again.")
  }

  
  oauthKey = cred@oauthKey = vals['oauth_token']
  oauthSecret = cred@oauthSecret = vals['oauth_token_secret']
  
  if (verify) {
    verifyURL <- paste(cred@authURL, "?oauth_token=",
                         oauthKey, sep='')
    msg <- paste("To enable the connection, please direct",
                 " your web browser to: \n",
                 verifyURL,
                 "\nWhen complete, record the PIN given ",
                 "to you and provide it here, or hit enter: ", sep='')
    browseURL(verifyURL)
    verifier <- readline(prompt = msg)
  } else
    verifier <- ""  
  
  params <- c(oauth_verifier = verifier)
  resp <- op(cred@accessURL, cred@consumerKey, cred@consumerSecret,
             cred@oauthKey, cred@oauthSecret, signMethod = cred@signMethod,
             curl = curl, params = params,
             handshakeComplete = FALSE, ..., callback = "oob")

  vals <- parseResponse(resp)
  if (!all(c('oauth_token', 'oauth_token_secret') %in%
           names(vals))) {
    stop("Invalid response after authorization.  ",
                       "You likely misentered your PIN, try rerunning",
                       " this handshake & browser authorization to get",
                       " a new PIN.")
  }

  cred@oauthKey = vals['oauth_token']
  cred@oauthSecret = vals['oauth_token_secret']  

  cred
}


OAuthRequest =
  function(cred, URL, params = character(), method = "GET",
           customHeader = NULL, curl = getCurlHandle(), ...) #, .opts = list())
{
    ' If the OAuth handshake has been completed, will
      submit a URL request with an OAuth signature, returning
      any response from the server
    '

    .self = as(cred, "OAuthCredentials")

    #XXX both OAuthCredentials and a reference class .self
    if (! length(.self@oauthSecret))
      stop("This OAuth instance has not been verified")

    httpFunc <- switch(method,
                       POST = oauthPOST,
                       GET = oauthGET,
                       PUT = oauthPUT,
                       DELETE = oauthDELETE,
                       HEAD = oauthHEAD,
                       stop("method must be POST, PUT, GET, DELETE or HEAD"))

    httpFunc(URLencode(URL), params = params,
             consumerKey = .self@consumerKey,
             consumerSecret = .self@consumerSecret,
             oauthKey = .self@oauthKey,
             oauthSecret = .self@oauthSecret,
             customHeader = customHeader, curl = curl, #XXX use customHeader in formals.
             signMethod = .self@signMethod, ...)#, .opts = .opts)
}
              


parseResponse <- function(response) {
  ## Will return a named vector, so a response field of the
  ## form foo=blah&qwerty=asdf will have vals c(blah,asdf) and
  ## names will be c(foo, qwerty).  If the response is borked,
  ## the output of this function will be as well, so caveat
  ## emptor, GIGO, etc

  if(is.raw(response))
    response = rawToChar(response)
  
  pairs <- sapply(strsplit(response, '&')[[1]], strsplit, '=')
  out <- sapply(pairs, function(x) x[2])
  names(out) <- sapply(pairs, function(x) x[1])
  out
}

oauthCommand <-
  function(url, consumerKey, consumerSecret,
           oauthKey, oauthSecret, params = character(), customHeader = NULL,
           curl = getCurlHandle(), signMethod = 'HMAC', ..., callback = character(), .command,
           .opts = list(...), .addwritefunction = TRUE)
{
  if(is.null(curl))
    curl <- getCurlHandle()

  
  auth <- signRequest(url, params, consumerKey, consumerSecret,
                      oauthKey = oauthKey, oauthSecret = oauthSecret,
                     httpMethod = .command, signMethod = signMethod, callback = callback)
                      

  if(!missing(.opts) && length(args <- list(...)))
     .opts = merge(.opts, args)
  .opts = addAuthorizationHeader(.opts, auth, oauthSecret, customHeader)

  if(.command == "PUT" && !("upload" %in% names(.opts)))
      .opts["upload"] = TRUE
  else if(!("customrequest" %in% names(.opts)))
       .opts[["customrequest"]] = toupper(.command)

  reader = NULL
  if(.addwritefunction) {
     reader <- dynCurlReader(curl, baseURL = url)
     .opts[["writefunction"]] = reader$update
  }

  ans = curlPerform(curl = curl, url = url, .opts = .opts)

  if(!is.null(reader))
    reader$value()
  else
     ans
}

oauthHEAD <- function(...)
   oauthCommand(..., .command = "HEAD", upload = TRUE)

oauthPUT <- function(...)
   oauthCommand(..., .command = "PUT", upload = TRUE)

oauthDELETE <- function(...) {
   oauthCommand(..., .command = "DELETE")
 }


oauthPOST <- function(url, consumerKey, consumerSecret,
                      oauthKey, oauthSecret, params = character(), customHeader = NULL,
                      curl = getCurlHandle(), signMethod = 'HMAC', handshakeComplete = TRUE,
                      ..., callback = character(), .opts = list(...)) {
  if(is.null(curl))
    curl <- getCurlHandle()
  
  auth <- signRequest(url, params, consumerKey, consumerSecret,
                      oauthKey = oauthKey, oauthSecret = oauthSecret,
                      httpMethod = "POST", signMethod = signMethod,
                      handshakeComplete = handshakeComplete, callback = callback)

  .opts = addAuthorizationHeader(.opts, auth, oauthSecret, customHeader)
  
  ## post ,specify the method
  ## We should be able to use postForm() but we have to work out the issues
  ## with escaping, etc. to match the signature mechanism.
  if (length(params) == 0) {
    reader <- dynCurlReader(curl, baseURL = url, verbose = FALSE)
    fields <- paste(names(auth), sapply(auth, curlPercentEncode),
                    sep = "=", collapse = "&")
    curlPerform(curl = curl, URL = url, postfields = fields,
                writefunction = reader$update, .opts = .opts)
    reader$value()
  } else
      postForm(url, .params = c(params, lapply(auth, I)), curl = curl,
                .opts = .opts, style = "POST")
}

#XXX? use .opts for the curl options.
#     add a ... for the parameters.

oauthGET <- function(url, consumerKey, consumerSecret,
                     oauthKey, oauthSecret, params=character(), customHeader = NULL,
                     curl = getCurlHandle(), signMethod='HMAC', handshakeComplete = TRUE,
                      ..., .opts = list(...), callback = character()) {
  ##   opts = list(httpheader = c(Authentication = paste(names(auth),  auth, sep = "=", collapse = "\n   ")), ...)
  if(is.null(curl))
    curl <- getCurlHandle()
   
   auth <- signRequest(url, params, consumerKey, consumerSecret,
                       oauthKey = oauthKey, oauthSecret = oauthSecret,
                       httpMethod = "GET", signMethod = signMethod, callback = callback)

   params <- c(params, as.list(auth))

  .opts$httpget = TRUE

  .opts = addAuthorizationHeader(.opts, auth, oauthSecret)

  
  getForm(url, .params = params, curl = curl, .opts = .opts)
}

addAuthorizationHeader =
    # Add the Authorization header field.  
function(.opts, auth, secret, customHeader = character())
{
 if(length(secret) == 0)  #  !("oauth_secret" %in% names(auth)) || auth[["oauth_secret"]] == "")
    return(.opts)

 if(length(customHeader))
   auth[names(customHeader)] = customHeader
 
  tmp = paste(names(auth), auth, sep = "=", collapse = ", ")

  if("httpheader" %in% names(.opts))
     .opts$httpheader[["Authorization"]] = sprintf('OAuth realm="", %s', tmp)
  else
     .opts$httpheader = c("Authorization" = sprintf('OAuth realm="", %s', tmp))

  .opts
}
