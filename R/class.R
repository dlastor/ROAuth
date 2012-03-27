setClass("OAuthCredentials",
          representation(consumerKey = "character",
                         consumerSecret = "character",
                         oauthKey = "character",
                         oauthSecret = "character",
                         requestURL = "character",
                         authURL = "character",
                         accessURL = "character",
                         signMethod = "character")  # could allow a function also.
         )


setMethod("$", "OAuthCredentials",
          function(x, name) {
            if(name == "handshake") {
                 function(...)
                     handshake(x, ...)
            
            } else if(tolower(name) %in% c("put", "delete")) {
               function(url, params = character(), ...) {
                 oauthCommand(url, x@consumerKey, x@consumerSecret, x@oauthKey, x@oauthSecret,
                                params, ..., .command = toupper(name))
               }
            } else if(name == "OAuthRequest") {
                 function(...)
                     OAuthRequest(x, ...)
            } else {
               f = switch(tolower(name),
                           get = oauthGET,
                           post = oauthPOST,
                           stop("no function for ", name))
               for(i in c("consumerKey", "consumerSecret", "oauthKey", "oauthSecret"))
                     formals(f)[[i]] = slot(x, i)
                   
               formals(f) = formals(f)[ c(1, 6:length(formals(f)), 2:5)]
               f
            }

          })
