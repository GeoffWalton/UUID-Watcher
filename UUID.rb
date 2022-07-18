require 'java'
require 'csv'
require 'thread'
java_import 'burp.IExtensionHelpers'

java_import 'javax.swing.JOptionPane'
java_import 'burp.ITab'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.JScrollPane'
java_import 'java.awt.Dimension'
java_import 'java.awt.Rectangle'
java_import 'java.awt.event.ComponentListener'


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

class AbstractBrupExtensionUI < JScrollPane
  include ITab
  include ComponentListener

  def initialize(extension)
    @panel = JPanel.new
    @panel.setLayout nil
    super(@panel)
    @extension = extension
    addComponentListener self
  end

  def extensionName
    @extension.extensionName
  end

  def add(component)
    bounds = component.getBounds
    updateSize(bounds.getX + bounds.getWidth, bounds.getY + bounds.getHeight)
    @panel.add component
  end

  alias_method :getTabCaption, :extensionName

  def getUiComponent
    self
  end

  private
  #Don't set the size smaller than existing widget positions
  def updateSize(x,y)
    x = (@panel.getWidth() > x) ? @panel.getWidth : x
    y = (@panel.getHeight() > y) ? @panel.getHeight : y
    @panel.setPreferredSize(Dimension.new(x,y))
  end

end

java_import('java.awt.Insets')
class AbstractBurpUIElement
  def initialize(parent, obj, positionX, positionY, width, height)
    @swingElement =obj
    setPosition parent, positionX, positionY, width, height
    parent.add @swingElement
  end

  def method_missing(method, *args, &block)
    @swingElement.send(method, *args)
  end

  private
  def setPosition(parent, x,y,width,height)
    insets = parent.getInsets
    size = @swingElement.getPreferredSize()
    w = (width > size.width) ? width : size.width
    h = (height > size.height) ? height : size.height
    @swingElement.setBounds(x + insets.left, y + insets.top, w, h)
  end
end

class BPanel < AbstractBurpUIElement
  include ComponentListener

  def initialize(parent, positionX, positionY, width, height)
    obj = JPanel.new
    obj.setLayout nil
    super parent, obj, positionX,positionY, width, height
  end
end

java_import 'javax.swing.JLabel'
class BLabel < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, align= :left)
    case align
    when :left
      a = 2
    when :right
      a = 4
    when :center
      a = 0
    else
      a = 2 #align left
    end
    super parent, JLabel.new(caption, a),positionX, positionY, width, height
  end
end

java_import 'javax.swing.JButton'
class BButton < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, &onClick)
    super parent, JButton.new(caption), positionX, positionY, width, height
    @swingElement.add_action_listener onClick
  end
end

java_import 'javax.swing.JSeparator'
class BHorizSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

class BVertSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, height)
    super parent, JSeparator.new(1), positionX, positionY, 1, height
  end
end

java_import 'javax.swing.JCheckBox'
class BCheckBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JCheckBox.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JTextField'
class BTextField < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JTextField.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JComboBox'
class BComboBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, &evt)
    super parent, JComboBox.new, positionX, positionY, width, height
    @swingElement.add_action_listener evt
  end
end

java_import 'javax.swing.JTextArea'
class BTextArea < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height)
    @textArea = JTextArea.new
    super parent, JScrollPane.new(@textArea), positionX, positionY, width, height
    @textArea.setLineWrap(true)
  end

  def setText(text)
    @textArea.setText text
  end

  def getText
    @textArea.getText
  end

  def setEditable(value)
    @textArea.setEditable(value)
  end
end

java_import 'burp.ITextEditor'
class BTextEditor < AbstractBurpUIElement
  def initialize(parent, callbacks, positionX, positionY, width, height)
    @textArea = callbacks.createTextEditor
    super parent, JScrollPane.new(@textArea.getComponent), positionX, positionY, width, height
  end

  def setText(text)
    @textArea.setText text.bytes
  end

  def getText
    @textArea.getText.map {|b| b.chr}.join
  end
end

java_import 'javax.swing.JMenuItem'
class BMenuItem < JMenuItem
  def initialize(text, &onClick)
    super(text)
    self.add_action_listener onClick
  end
end

#########################################################################################
#Begin Burp Extension
#########################################################################################
java_import 'burp.IScannerCheck'
java_import 'burp.IScanIssue'
class UUIDCorrelationScanCheck
  include IScannerCheck
  include BURPMethods

  GUID_MIN_UNIQ_BYTES = 7
  GUID_RE = /(?:[0-9a-fA-F]{8}(?:(?:-|%2d|%2D)?[0-9a-fA-F]{4}){3}(?:-|%2d|%2D)?[0-9a-fA-F]{12})/

  #inner class to hold some request details
  class UUIDParameterInfo
    attr_accessor :name
    attr_writer :type
    attr_accessor :uuid

    def eql?(other)
      self.name == other.name && self.type == other.type && self.uuid == other.uuid
    end

    alias_method :==, :eql?

    def type
      return @type if @type.kind_of? String
      case @type
      when 0
        'url'
      when 1
        'body'
      when 2
        'Cookie'
      when 3
        'XML'
      when 4
        'XML attribute'
      when 5
        'multipart attribute'
      when 6
        'JSON'
      else
        'Unknown/Undefined'
      end
    end

    def initialize(parameter = nil)
      if parameter
        @name = parameter.getName
        @type = parameter.getType
      end
    end
  end

  #Satisfy interface requirements
  def doActiveScan(baseRequestResponse, insertionPoint); nil; end
  def consolidateDuplicateIssues(existingIssue, newIssue); 0; end

  def initialize
    super
    @responseUUIDS = Hash.new
    @requestUUIDS = Hash.new
    @sync = Mutex.new
  end

  def doPassiveScan(baseRequestResponse)
    #Find the 'base url'
    reqInfo = analyzeRequest(baseRequestResponse.getHttpService, baseRequestResponse.getRequest)
    url = reqInfo.getUrl
    short_url = "#{url.protocol}://#{url.host}/#{url.path}"

    #Are there any strings that look like UUIDs/Guids in identifiable request parameters?
    #special case URL path
    findUUIDs(url.path).each do |uuid|
      a = @requestUUIDS[short_url] || Array.new
      item = UUIDParameterInfo.new
      item.name = '"url path"'
      item.uuid = uuid
      item.type = 0
      a << item
      @sync.synchronize { @requestUUIDS[short_url] = a } #set in case array was a new object
    end
    params = reqInfo.getParameters.to_array
    params.each do |param|
      findUUIDs(param.getValue).each do |uuid|
        a = @requestUUIDS[short_url] || Array.new
        item = UUIDParameterInfo.new(param)
        item.uuid = uuid
        a << item
        @sync.synchronize { @requestUUIDS[short_url] = a } #set in case array was a new object
      end
    end
    @requestUUIDS[short_url].uniq! {|item| item.uuid} if @requestUUIDS[short_url]

    findUUIDs(bytesToString(baseRequestResponse.getResponse)).each do |uuid|
      a = @responseUUIDS[short_url] || Array.new
      a << uuid
      @sync.synchronize { @responseUUIDS[short_url] = a }
    end
    @responseUUIDS[short_url].uniq! if @responseUUIDS[short_url]
    nil #Need explit return for interface
  end

  def writeReport
    @sync.synchronize do
      matches = Array.new
      @requestUUIDS.each do |url, parameters|
        parameters.each do |parameter|
          @responseUUIDS.each do |src_url, uuids|
            next if src_url == url #Ignore if the UUID is just reflected in a response
            if uuids.include? parameter.uuid
              item = Array.new
              p = parameter.dup
              p.uuid = nil
              item << url; item << p.name; item << p.type; item << src_url
              matches << item
            end
          end
          matches.uniq!
        end
      end
      matches.unshift ['URL', 'Parameter', 'Type', 'Source URL']
      matches.map!(&:to_csv)
      matches.join
    end
  end

  private

  #return an array of normalized UUID strings
  def findUUIDs(str)
    uuids = str.to_s.scan(GUID_RE) #convert from Java String to ruby string if needed
    uuids.map! do |uuid|
      uuid.tr! '-', ''
      uuid.downcase!
      ( uuid.sub('%2d', '') || uuid )
    end

    uuids.reject! {|uuid| uuid.bytes.uniq.count <= GUID_MIN_UNIQ_BYTES }
    uuids.uniq
  end
end

java_import 'burp.IContextMenuFactory'
class UUIDCorrelationContextMenuFactory
  include IContextMenuFactory
  CONTEXT_TARGET_SITE_MAP_TREE = 4;

  def initialize(scannerInstance)
    @ScannerInstance = scannerInstance
  end

  def createMenuItems(invocation)
    return nil unless invocation.getInvocationContext.to_i == CONTEXT_TARGET_SITE_MAP_TREE
    i = BMenuItem.new("Write UUID Correlation Report to ~/UUID_MAP.csv") do
      File.write("#{ENV['HOME']}/UUID_MAP.csv", @ScannerInstance.writeReport)
    end
    [i]
  end
end

java_import 'burp.IBurpExtender'
class BurpExtender
  include IBurpExtender
  ExtensionName = 'UUID'

  def registerExtenderCallbacks(callbacks)

    ###DEBUG
    #java.lang.System.setProperty('jruby.home', '/opt/jruby-9.1.0.0')
    #java.lang.System.setProperty('jruby.lib', '/opt/jruby-9.1.0.0/lib')
    #require 'pry'
    #require 'pry-nav'
    ###END

    callbacks.setExtensionName ExtensionName
    ObjectSpace.each_object(Class).select {|klass| klass < BURPMethods }.each do |kklass|
      kklass.callbacks = callbacks
    end
    scanner = UUIDCorrelationScanCheck.new
    callbacks.registerScannerCheck(scanner)
    callbacks.registerContextMenuFactory UUIDCorrelationContextMenuFactory.new(scanner)
    Thread.new { binding.pry }
  end

end