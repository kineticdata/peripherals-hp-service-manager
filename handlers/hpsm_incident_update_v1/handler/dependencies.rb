require 'time'

# Load the JRuby Open SSL library unless it has already been loaded.  This
# prevents multiple handlers using the same library from causing problems.
if not defined?(Jopenssl)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))

  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/bouncy-castle-java-1.5.0146.1/lib')
  $:.unshift library_path
  # Require the library
  require 'bouncy-castle-java'

  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/jruby-openssl-0.7.7/lib/1.8')
  $:.unshift library_path
  library_path = File.join(handler_path, 'vendor/jruby-openssl-0.7.7/lib/shared')
  $:.unshift library_path
  # Require the library
  require 'openssl'
  # Require the version constant
  require 'jopenssl/version'
end

# Validate the the loaded openssl library is the library that is expected for
# this handler to execute properly.
if not defined?(Jopenssl::Version::VERSION)
  raise "The Jopenssl class does not define the expected VERSION constant."
elsif Jopenssl::Version::VERSION != '0.7.7'
  raise "Incompatible library version #{Jopenssl::Version::VERSION} for Jopenssl.  Expecting version 0.7.7."
end



# Load the ruby Rack library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Rack)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/rack-1.4.1/lib')
  $:.unshift library_path
  # Require the library
  require 'rack'
end

# Validate the the loaded Rack library is the library that is expected for
# this handler to execute properly.
if not defined?(Rack.release)
  raise "The Rack class does not define the expected VERSION constant."
elsif Rack.release != '1.4'
  raise "Incompatible library version #{Rack.release} for Rack.  Expecting version 1.4."
end



# Load the HTTP Client library unless it has already been loaded.  This
# prevents multiple handlers using the same library from causing problems.
if not defined?(HTTPClient)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/httpclient-2.2.5/lib')
  $:.unshift library_path
  # Require the library
  require 'httpclient'
end

# Validate the the loaded openssl library is the library that is expected for
# this handler to execute properly.
if not defined?(HTTPClient::VERSION)
  raise "The HTTPClient class does not define the expected VERSION constant."
elsif HTTPClient::VERSION != '2.2.5'
  raise "Incompatible library version #{HTTPClient::VERSION} for HTTPClient.  Expecting version 2.2.5."
end




# Load the ruby JSON library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(JSON)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/json-1.8.0/lib')
  $:.unshift library_path
  # Require the library
  require 'json'
end

# Validate the the loaded JSON library is the library that is expected for
# this handler to execute properly.
if not defined?(JSON::VERSION)
  raise "The JSON class does not define the expected VERSION constant."
elsif JSON::VERSION != '1.8.0'
  raise "Incompatible library version #{JSON::VERSION} for JSON.  Expecting version 1.8.0."
end




# Load the ruby Builder library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Builder)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/builder-3.0.0/lib')
  $:.unshift library_path
  # Require the library
  require 'builder'
end

# Validate the the loaded Builder library is the library that is expected for
# this handler to execute properly.
if not defined?(Builder::VERSION)
  raise "The Builder class does not define the expected VERSION constant."
elsif Builder::VERSION != '3.0.0'
  raise "Incompatible library version #{Builder::VERSION} for Builder.  Expecting version 3.0.0."
end




# Load the ruby Gyoku library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Gyoku)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/gyoku-0.4.5/lib')
  $:.unshift library_path
  # Require the library
  require 'gyoku'
end

# Validate the the loaded Gyoku library is the library that is expected for
# this handler to execute properly.
if not defined?(Gyoku::VERSION)
  raise "The Gyoku class does not define the expected VERSION constant."
elsif Gyoku::VERSION != '0.4.5'
  raise "Incompatible library version #{Gyoku::VERSION} for Gyoku.  Expecting version 0.4.5."
end




# Load the ruby Akami library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Akami)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/akami-1.1.0/lib')
  $:.unshift library_path
  # Require the library
  require 'akami'
end

# Validate the the loaded Akami library is the library that is expected for
# this handler to execute properly.
if not defined?(Akami::VERSION)
  raise "The Akami class does not define the expected VERSION constant."
elsif Akami::VERSION != '1.1.0'
  raise "Incompatible library version #{Akami::VERSION} for Akami.  Expecting version 1.1.0."
end




# Load the ruby Httpi library unless it has already been loaded. 
# This prevents multiple handlers using the same library from causing problems.
if not defined?(HTTPI)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/httpi-1.0.0/lib')
  $:.unshift library_path
  # Require the library
  require 'httpi'
end

# Validate the the loaded Httpi library is the library that is expected for
# this handler to execute properly.
if not defined?(HTTPI::VERSION)
  raise "The Httpi class does not define the expected VERSION constant."
elsif HTTPI::VERSION != '1.0.0'
  raise "Incompatible library version #{HTTPI::VERSION} for Httpi.  Expecting version 1.0.0."
end





# Load the ruby Nokogiri library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Nokogiri)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/nokogiri-1.5.3-java/lib')
  $:.unshift library_path
  # Require the library
  require 'nokogiri'
  require 'nokogiri/version'
end

# Validate the the loaded Nokogiri library is the library that is expected for
# this handler to execute properly.
if not defined?(Nokogiri::VERSION)
  raise "The Nokogiri class does not define the expected VERSION constant."
elsif Nokogiri::VERSION != '1.5.3'
  raise "Incompatible library version #{Nokogiri::VERSION} for Nokogiri.  Expecting version 1.5.3."
end




# Load the ruby Nori library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Nori)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/nori-1.1.0/lib')
  $:.unshift library_path
  # Require the library
  require 'nori' 
end

# Validate the the loaded Nori library is the library that is expected for
# this handler to execute properly.
if not defined?(Nori::VERSION)
  raise "The Nori class does not define the expected VERSION constant."
elsif Nori::VERSION != '1.1.0'
  raise "Incompatible library version #{Nori::VERSION} for Nori.  Expecting version 1.1.0."
end





# Load the ruby Wasabi library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Wasabi)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/wasabi-2.4.1/lib')
  $:.unshift library_path
  # Require the library
  require 'wasabi'
end

# Validate the the loaded Wasabi library is the library that is expected for
# this handler to execute properly.
if not defined?(Wasabi::VERSION)
  raise "The Wasabi class does not define the expected VERSION constant."
elsif Wasabi::VERSION != '2.4.1'
  raise "Incompatible library version #{Wasabi::VERSION} for Wasabi.  Expecting version 2.4.1."
end




# Load the ruby Savon library unless it has already been loaded.  This prevents
# multiple handlers using the same library from causing problems.
if not defined?(Savon)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/savon-1.0.0/lib')
  $:.unshift library_path
  # Require the library
  require 'savon'
end

# Validate the the loaded Savon library is the library that is expected for
# this handler to execute properly.
if not defined?(Savon::VERSION)
  raise "The Savon class does not define the expected VERSION constant."
elsif Savon::VERSION != '1.0.0'
  raise "Incompatible library version #{Savon::VERSION} for Savon.  Expecting version 1.0.0."
end