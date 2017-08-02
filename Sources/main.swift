//
//  JSSAPI.swift
//  
//
//  Created by Andrew Bitson on 5/12/16.
//  Modified for my use by jsinger on 7.31.17
//

import SwiftyJSON
import Foundation

// Usage: QueryCasper -f json_authorization_file.txt -p sub_url or
//        QueryCasper -u username:password -p sub_url 
// NOTE: -f & -u are mutually-exclusive

class JSS {
    
    private var _urlString: String = ""
    private var _auth: String = ""
    private var _url: URL
    
    var urlString: String {
        get {
            return _urlString
        } set {
            _urlString = newValue
        }
    }

    var auth: String {
        get {
            return _auth
        } set {
            _auth = newValue
        }
    }
   
    var url: URL {
        get {
            return _url
        } set {
            _url = newValue
        }
    }
    
    init(with serverURL: String, ac: Int32, cmdLine:  UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>) {
        let pattern = "f:u:p:"
        var fFlag = false
        var fVal: String?
        
        var uFlag = false
        var uValue: String?
        
        var pFlag = false
        var pValue: String?

        let jamfUsername: String? = nil, jamfPassword: String? = nil

        self._url = URL(string: "\(serverURL)/JSSResource")!

        while case let option = getopt(ac, cmdLine, pattern), option != -1 {
            switch UnicodeScalar(CUnsignedChar(option)) {
            case "u":
                uFlag = true
                uValue = String(cString: optarg)
                
            case "f":
                fFlag = true
                fVal = String(cString: optarg)
                
            case "p":
                pFlag = true
                pValue = String(cString: optarg)
                
            default:
//                print("Unknown Option: \(cmdLine.arguments)")
                print("Unknown Option")
                exit(EXIT_FAILURE)
            }
        }

        // the following is the same thing as a logical XOR
        guard  uFlag != fFlag else {
            print("-u or -f, Either command-line flag option may be used; not both")
            exit(EXIT_FAILURE)
        }
        
        
        print("fFlag = \(fFlag) and fValue = ", fVal ?? "?")
        print("uFlag = \(uFlag) and uValue = ", uValue ?? "?", "\n")
        print("pFlag = \(pFlag) and pValue = ", pValue ?? "?", "\n")
        
        // Now, if the fFlag is set, we've gotten our parameter file from the command-line, so we'll try to read it, parse, it and
        //    use it to access JAMF.
        if fFlag {
            do {
                guard let filedata = try? String(contentsOfFile: fVal!, encoding: String.Encoding.utf8) else { return }
        
                if let authProps = filedata.data(using: String.Encoding.utf8, allowLossyConversion: false) {
                    let json = JSON(data: authProps)
                    let user = json["username"].string
                    let password = json["password"].string
                    let loginData = String(format: "%@:%@", user!, password!).data(using: String.Encoding.utf8)!
//                    let base64LoginData = loginData.base64EncodedString()
                    self.auth = loginData.base64EncodedString()
        
//        self.auth = "\(jamfUsername):\(jamfPassword)".dataUsingEncoding(NSUTF8StringEncoding)!.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)

                    }
            }
        }
    
    func getComputerRecord(serialNumber: String, completionHandler: (NSData?, URLResponse?, NSError?) -> Void) {
        
        let request = URLRequest(url: (URL(string: "\(.url)/computers/match/" + serialNumber ))!)
        request.HTTPMethod = "GET"
        request.addValue("application/xml", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        
        let session = URLSession.sharedSession()
        session.dataTaskWithRequest(request, completionHandler: completionHandler).resume()
    }


    func createPlaceholder(serialNumber: String, macAddress: String, completionHandler: (NSData?, URLResponse?, NSError?) -> Void) {
        let xml = "<computer>" +
                    "<general>" +
                        "<name>Placeholder-\(serialNumber)</name>" +
                        "<serial_number>\(serialNumber)</serial_number>" +
                        "<mac_address>\(macAddress)</mac_address>" +
                    "</general>" +
                "</computer>"
        
        let request = NSMutableURLRequest(URL: (NSURL(string: "\(.url)/computers/id/0"))!)
        request.HTTPMethod = "POST"
        request.addValue("application/xml", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        request.HTTPBody = xml.dataUsingEncoding(NSUTF8StringEncoding)
        
        let session = URLSession.sharedSession()
        session.dataTaskWithRequest(request, completionHandler: completionHandler).resume()
    }
    
    func addComputerToGroup(serialNumber: String, groupName: String, completionHandler: (NSData?, URLResponse?, NSError?) -> Void) {
        let xml = "<computer_group>" +
                    "<computer_additions>" +
                        "<computer>" +
                            "<serial_number>\(serialNumber)</serial_number>" +
                        "</computer>" +
                    "</computer_additions>" +
                "</computer_group>"
        
        let urlEncodedGroupName = groupName.stringByAddingPercentEncodingWithAllowedCharacters(.URLHostAllowedCharacterSet())!
        
        let request = NSMutableURLRequest(URL: (NSURL(string: "\(.url)/computergroups/name/\(urlEncodedGroupName)"))!)
        request.HTTPMethod = "PUT"
        request.addValue("application/xml", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        request.HTTPBody = xml.dataUsingEncoding(NSUTF8StringEncoding)
        
        let session = URLSession.sharedSession()
        session.dataTaskWithRequest(request, completionHandler: completionHandler).resume()
    }
    
    func removeComputerFromGroup(serialNumber: String, groupName: String, completionHandler: (NSData?, URLResponse?, NSError?) -> Void) {
        let xml = "<computer_group>" +
                    "<computer_deletions>" +
                        "<computer>" +
                            "<serial_number>\(serialNumber)</serial_number>" +
                        "</computer>" +
                    "</computer_deletions>" +
                "</computer_group>"
        
        let urlEncodedGroupName = groupName.stringByAddingPercentEncodingWithAllowedCharacters(.URLHostAllowedCharacterSet())!
        let request = NSMutableURLRequest(URL: (NSURL(string: "\(.url)/computergroups/name/\(urlEncodedGroupName)"))!)
        request.HTTPMethod = "PUT"
        request.addValue("application/xml", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        request.HTTPBody = xml.dataUsingEncoding(NSUTF8StringEncoding)
        
        let session = URLSession.sharedSession()
        session.dataTaskWithRequest(request, completionHandler: completionHandler).resume()
    }
    
    func getGroups(completionHandler: (NSData?, URLResponse?, NSError?) -> Void) {
        
        let request = NSMutableURLRequest(URL: (NSURL(string: "\(.url)/computergroups"))!)
        request.HTTPMethod = "GET"
        request.addValue("application/xml", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(auth)", forHTTPHeaderField: "Authorization")
        
        let session = URLSession.sharedSession()
        session.dataTaskWithRequest(request, completionHandler: completionHandler).resume()
    }
    }
}

// *** Start of main logic
let baseUrl = "https://casper.csueastbay.edu:8443"

let jss = JSS(baseUrl, CommandLine.argc, CommandLine.arguments)

var urlRequest = URLRequest(url: jss.url!,
                            cachePolicy: .reloadIgnoringLocalCacheData,
                            timeoutInterval: 10.0 * 1000)

urlRequest.httpMethod = "GET"
urlRequest.addValue("Basic \(jss.auth!)", forHTTPHeaderField: "Authorization")
urlRequest.addValue("application/json", forHTTPHeaderField: "Accept")

let task = URLSession.shared.dataTask(with: urlRequest) {
        (data, response, error) -> Void in
    
    guard let data = data, error == nil else {
        print("Error while fetching data: \(String(describing: error))")
        exit(EXIT_FAILURE)
    }

    if let httpStatus = response as? HTTPURLResponse {
        print("status code = \(httpStatus.statusCode)")
        print("headers = \(httpStatus.allHeaderFields)")
    } else {
        print("data is: \(data)")
    }
}
task.resume()

