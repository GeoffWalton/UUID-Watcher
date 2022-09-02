require 'java'
require 'csv'
require 'thread'

java_import 'javax.swing.JMenuItem'
class BMenuItem < JMenuItem
  def initialize(text, &onClick)
    super(text)
    self.add_action_listener onClick
  end
end

java_import 'javax.swing.JOptionPane'
java_import 'javax.swing.JFileChooser'
java_import 'javax.swing.filechooser.FileNameExtensionFilter'
class BFileChooser
  attr_writer :directory

  def initialize(parent=nil, directory=nil)
    @parent = parent
    @filter = nil
    @directory = directory
  end

  def filter(description, *extensions)
    @filter = FileNameExtensionFilter.new description, *extensions
    self
  end

  def prompt(text, &block)
    chooser = obj
    return nil unless JFileChooser::APPROVE_OPTION == chooser.showDialog(@parent, text)
    f = chooser.getSelectedFile
    return nil unless f.isFile
    block.call f.getAbsoluteFile.to_s
  end

  private
  def obj
    o = @directory ? JFileChooser.new(@directory) : JFileChooser.new
    o.setFileFilter @filter if @filter
    o
  end
end

module BURPMethods
  def self.included(base)
    base.send(:include,InstanceMethods)
    base.extend(StaticMethods)
  end

  module InstanceMethods
    def method_missing(method, *args, &block)
      if self.class.helpers.respond_to? method
        self.class.helpers.send(method, *args, &block)
      elsif self.class.callbacks.respond_to? method
        self.class.callbacks.send(method, *args, &block)
      else
        raise NoMethodError, "undefined method `#{method}` for #{self.class.name}"
      end
    end

    def respond_to?(method, include_private = false)
      super || self.class.callbacks.respond_to?(method, include_private) || self.class.helpers.respond_to?(method, include_private)
    end

  end

  module StaticMethods
    def callbacks=(callbacks)
      @callbacks = callbacks
      @helpers = @callbacks.getHelpers
    end

    attr_reader :callbacks
    attr_reader :helpers
  end
end

java_import 'burp.IParameter'
java_import 'burp.IContextMenuInvocation'
java_import 'burp.IRequestInfo'
module BURPEnums

  ParameterTypes = {
 Java::Burp::IParameter::PARAM_URL => :url,
 Java::Burp::IParameter::PARAM_BODY => :body,
 Java::Burp::IParameter::PARAM_COOKIE => :cookie,
 Java::Burp::IParameter::PARAM_XML => :XML,
 Java::Burp::IParameter::PARAM_XML_ATTR => :XML_Attribute,
 Java::Burp::IParameter::PARAM_MULTIPART_ATTR => :XML_Multipart,
 Java::Burp::IParameter::PARAM_JSON => :JSON,
  }
  ParameterTypes.default = :undefined
  ParameterTypes.freeze

  ContextMenuInvocation = {
    Java::Burp::IContextMenuInvocation::CONTEXT_MESSAGE_EDITOR_REQUEST => :editor_request,
    Java::Burp::IContextMenuInvocation::CONTEXT_MESSAGE_EDITOR_RESPONSE => :editor_response,
    Java::Burp::IContextMenuInvocation::CONTEXT_MESSAGE_VIEWER_REQUEST => :viewer_request,
    Java::Burp::IContextMenuInvocation::CONTEXT_MESSAGE_VIEWER_RESPONSE => :viewer_response,
    Java::Burp::IContextMenuInvocation::CONTEXT_TARGET_SITE_MAP_TREE => :site_map_tree,
    Java::Burp::IContextMenuInvocation::CONTEXT_TARGET_SITE_MAP_TABLE => :site_map_table,
    Java::Burp::IContextMenuInvocation::CONTEXT_PROXY_HISTORY => :proxy_history,
    Java::Burp::IContextMenuInvocation::CONTEXT_SCANNER_RESULTS => :scanner_results,
    Java::Burp::IContextMenuInvocation::CONTEXT_INTRUDER_PAYLOAD_POSITIONS => :intruder_payload_position,
    Java::Burp::IContextMenuInvocation::CONTEXT_INTRUDER_ATTACK_RESULTS => :intruder_attack_result,
    Java::Burp::IContextMenuInvocation::CONTEXT_SEARCH_RESULTS => :search_results
  }
  ContextMenuInvocation.freeze

end
#########################################################################################
#Begin Burp Extension
#########################################################################################

class UUIDCorrelation
  include BURPMethods
  include BURPEnums

  GUID_RE = /(?:[0-9a-fA-F]{8}(?:(?:-|%2d|%2D)?[0-9a-fA-F]{4}){3}(?:-|%2d|%2D)?[0-9a-fA-F]{12})/
  GQL_REQUEST_RE = /query":"(?<type>query|mutation)\s(?<name>\w*)/
  GQL_REQUEST_Q_RE = /(?<type>query)=\{(?<name>\w*)\{/
  GQL_RESPONSE_RE = /"data":{/

  module UUID_UTIL
    def normalize(uuid)
      t = uuid.tr '-', ''
      t.downcase!
      [( t.sub('%2d', '') || t )].pack 'H*'
    end

    def uuidToString(uuid)
      x.bytes.map {|x| x.to_s(16) }.join
    end
  end

  class ResponseIds
    #collect and de-dupe url, uuid pairs

    include UUID_UTIL

    def initialize
      @sync = Mutex.new
      @items = Hash.new
    end

    def clear
      @sync.synchronize { @items.clear }
    end

    def add(url, uuid)
      id = normalize uuid
      @sync.synchronize do
        urls = @items[id] || Array.new
        urls << url unless urls.include? url
        @items[id] = urls
      end
    end

    def [](uuid)
      #id = normalize uuid
      @sync.synchronize do
        @items[uuid]
      end
    end
  end

  class RequestIds
    #collect and de-dupe, uuid, url, parameter, and parameter type tuples
    # cheat and leverage the member equality and #hash properties of structs to find dupes

    include UUID_UTIL
    include BURPEnums
    Key = Struct.new(:url, :method, :parameter, :parameterType, :gqlType, :gqlOperation)

    def initialize
      @sync = Mutex.new
      @items = Hash.new
    end

    def clear
      @sync.synchronize { @items.clear }
    end

    def add(url, method, name, type, uuid, gqlType = nil, gqlOperation = nil)
      id = normalize uuid
      key = Key.new(url.to_s, method.to_s, name.to_s, type, gqlType, gqlOperation.to_s)
      @sync.synchronize do
        uuids = @items[key] || Array.new
        uuids << id unless uuids.include? id
        @items[key] = uuids
      end
    end

    def each(&block)
      @sync.synchronize { @items.send :each, &block }
    end

  end

  def initialize
    @responseUUIDS = ResponseIds.new
    @requestUUIDS = RequestIds.new
  end

  def ignoreCookies
    @ignoreCookies ||= false
  end

  def ignoreCookies!
    @ignoreCookies = !ignoreCookies
  end

  def clear
    @responseUUIDS.clear
    @requestUUIDS.clear
  end

  def scan(baseRequestResponse)
    return if (baseRequestResponse.getRequest.nil? or baseRequestResponse.getResponse.nil?)
    requestInfo = analyzeRequest(baseRequestResponse.getHttpService, baseRequestResponse.getRequest)

    url = requestInfo.getUrl
    short_url = "#{url.protocol}://#{url.host}#{url.path}"

    response = bytesToString(baseRequestResponse.getResponse).to_s
    #try and determine if this is GraphQL
    gqlType, gqlOperation = checkGraphQL(baseRequestResponse, requestInfo, response, url)

    #Grab response UUIDs
    response.scan(GUID_RE).each { |uuid| @responseUUIDS.add [short_url, gqlOperation], uuid }

    #Grap request UUIDs
    parameters = requestInfo.getParameters.to_array
    parameters.each do |parameter|
      value = parameter.getValue.to_s
      value.scan(GUID_RE).each {|uuid| @requestUUIDS.add(short_url, requestInfo.getMethod,
                                                         parameter.getName,
                                                         ParameterTypes[parameter.getType],
                                                         uuid,
                                                         gqlType,
                                                         gqlOperation)}
    end

    #special case of url "path parameter"
    index = 0
    url.path.to_s.scan(GUID_RE).each {|uuid|
      @requestUUIDS.add(short_url, requestInfo.getMethod, "idx #{index}",
                        :url_path, uuid,nil,nil)
    }
  end

  def report
    matches = Array.new
    @requestUUIDS.each do |tuple, uuids|
      next if (tuple[:parameterType] == :cookie) and ignoreCookies
      uuids.each do |uuid|
        urls = @responseUUIDS[uuid]
        urls.each {|url| a = [tuple, url]; matches << a unless matches.include? a } if urls
      end
    end
    csv = CSV.generate do |report|
      report << ['URL', 'Method', 'Parameter', 'Parameter Type', 'GraphQL Type',
                 'GraphQL Operation', 'Source URL', 'Source GraphQL Operation']
      matches.each do |record|
        report << (record[0].to_a + record[1])
      end
    end
    csv
  end

  private

  def checkGraphQL(baseRequestResponse, requestInfo, response, url)
    q = d = gqlType = gqlOperation = nil

    case requestInfo.getMethod
    when 'POST'
      if Java::Burp::IRequestInfo::CONTENT_TYPE_JSON == requestInfo.getContentType
        q = GQL_REQUEST_RE.match bytesToString(baseRequestResponse.getRequest).to_s
        d = GQL_RESPONSE_RE.match response
      end
    when 'GET'
      d = GQL_RESPONSE_RE.match response
      q = url.getQuery.to_s.scan(GQL_REQUEST_Q_RE)[0]
    end
    unless (q.nil? and d.nil?)
      gqlType ||= q['type']
      gqlOperation = q['name']
    end
    [gqlType, gqlOperation]
  rescue => e
    [nil,nil]
  end

end

java_import 'burp.IContextMenuFactory'
class UUIDCorrelationContextMenuFactory
  include IContextMenuFactory
  include BURPMethods
  include BURPEnums

  def initialize(scannerInstance)
    @ScannerInstance = scannerInstance
  end

  def createMenuItems(invocation)
    return nil unless invocation.getInvocationContext == ContextMenuInvocation.invert[:site_map_tree]
    component = invocation.getInputEvent.getComponent
    items = Array.new

    items << BMenuItem.new("Write UUID Correlation Report to File") do
      Thread.new do
      BFileChooser.new(component).filter('Comma-seperated Values', "csv").prompt("Save-As") do |pathspec|
        File.write(pathspec, @ScannerInstance.report)
        JOptionPane.showMessageDialog(component,"Wrote file - #{pathspec}", 'Finished!', JOptionPane::INFORMATION_MESSAGE)
      end
      end
    end

    items << BMenuItem.new("Add URL Prefix to Correlation Data") do
      Thread.new do
        cnt = 0
        invocation.getSelectedMessages.to_a.each do |message|
          url = analyzeRequest(message).getUrl
          prefix = url.to_s
          #Fix some url patterns
          prefix.sub! ":443", '' if (url.port == 443 and url.protocol == 'https')
          prefix.sub! ":80", '' if (url.port == 80 and url.protocol == 'http')
          getSiteMap(prefix).to_a.each do |i|
            @ScannerInstance.scan i
            cnt += 1
          end
        end
        JOptionPane.showMessageDialog(component,"Scanned #{cnt} item(s).", 'Scan Result', JOptionPane::INFORMATION_MESSAGE)
      end
    end

    items << BMenuItem.new("Clear Correlation Data") do
      @ScannerInstance.clear
      JOptionPane.showMessageDialog(component,"All Fresh and Clean!", 'Items Cleared', JOptionPane::INFORMATION_MESSAGE)
    end

    unless @ScannerInstance.ignoreCookies
      items << BMenuItem.new('Ignore Cookies') { @ScannerInstance.ignoreCookies! }
    else
      items << BMenuItem.new('Report Cookies') { @ScannerInstance.ignoreCookies! }
    end

    items
  end
end


java_import 'burp.IBurpExtender'
class BurpExtender
  include IBurpExtender
  ExtensionName = 'UUID'

  def registerExtenderCallbacks(callbacks)

    callbacks.setExtensionName ExtensionName
    ObjectSpace.each_object(Class).select {|klass| klass < BURPMethods }.each do |kklass|
      kklass.callbacks = callbacks
    end
    callbacks.registerContextMenuFactory UUIDCorrelationContextMenuFactory.new(UUIDCorrelation.new)

  end

end