# Require the dependencies file to load the vendor libraries
require File.expand_path(File.join(File.dirname(__FILE__), 'dependencies'))

class HpsmIncidentActivityAddV1
  def initialize(input)
    # Set the input document attribute
    @input_document = REXML::Document.new(input)

    # Store the info values in a Hash of info names to values.
    @info_values = {}
    REXML::XPath.each(@input_document,"/handler/infos/info") { |item|
      @info_values[item.attributes['name']] = item.text
    }
    @enable_debug_logging = @info_values['enable_debug_logging'] == 'Yes'

    # Store parameters values in a Hash of parameter names to values.
    @parameters = {}
    REXML::XPath.match(@input_document, '/handler/parameters/parameter').each do |node|
      @parameters[node.attribute('name').value] = node.text.to_s
    end
  end

  def execute()
    puts "Configuring Savon" if @enable_debug_logging
    if !@enable_debug_logging
      Savon.configure do |config|
        config.log = false
        config.log_level = :error
        HTTPI.log = false
      end
    end

    server_address = @info_values['server_address']
    client = Savon::Client.new do |wsdl,http,wsse|
      http.auth.basic "falcon", ""
      wsdl.document = server_address.gsub(/\/$/,"") + "/sc62server/PWS/IncidentManagement.wsdl"
    end

    soap_dict = {:"ins0:model" => 
      {:"ins0:keys" => 
        {:"ins0:IncidentID" => @parameters['incident_id']}
      }, 
     :"ins0:instance" => {
       :"ins0:IncidentID" => @parameters['incident_id'],
       :"ins0:JournalUpdates" => {:"ins0:JournalUpdates" => @parameters['activity_update']}, :attributes! => {:"ins0:JournalUpdates" => {:type => "Array"}}
      },
     :"ins0:messages" => {:"com:message" => ""}
    }

    soap_xml = Gyoku.xml(soap_dict)

    begin
      # SOAP request to get list contents
      response = client.request(:update_incident) do
        soap.namespaces["xmlns:com"] = "http://servicecenter.peregrine.com/PWS/Common"
        soap.body = soap_xml
      end
    # Wrapping the errors for human readability
    rescue Savon::HTTP::Error => error
      if error.http.code == 401
        raise StandardError, "Invalid Username/Password Combination and/or insufficient privileges"
      else
        raise
      end
    rescue Exception => ex
      if ex.class.to_s == "SocketError"
        raise StandardError, "Connection Failed: Invalid URL"
      else
        raise
      end
    end

    if response.body[:update_incident_response][:@status] != "SUCCESS"
      if response.body[:update_incident_response][:messages] != nil
        message = response.body[:update_incident_response][:messages][:message]
      else
        message = response.body[:update_incident_response][:@message]
      end
      raise StandardError, message
    end

    if response.body[:update_incident_response][:messages][:message].is_a?(Array)
      messages = response.body[:update_incident_response][:messages][:message].join(" -- ")
    else
      messages = response.body[:update_incident_response][:messages][:message]
    end
    
    # Return the results
    <<-RESULTS
    <results>
      <result name="incident_id">#{response.body[:update_incident_response][:model][:keys][:incident_id]}</result>
      <result name="messages">#{messages}</result>
    </results>
    RESULTS
  end


  # This is a template method that is used to escape results values (returned in
  # execute) that would cause the XML to be invalid.  This method is not
  # necessary if values do not contain character that have special meaning in
  # XML (&, ", <, and >), however it is a good practice to use it for all return
  # variable results in case the value could include one of those characters in
  # the future.  This method can be copied and reused between handlers.
  def escape(string)
    # Globally replace characters based on the ESCAPE_CHARACTERS constant
    string.to_s.gsub(/[&"><]/) { |special| ESCAPE_CHARACTERS[special] } if string
  end
  # This is a ruby constant that is used by the escape method
  ESCAPE_CHARACTERS = {'&'=>'&amp;', '>'=>'&gt;', '<'=>'&lt;', '"' => '&quot;'}

end