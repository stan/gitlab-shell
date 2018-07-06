require 'net/http'
require 'openssl'
require 'json'

require_relative 'gitlab_config'
require_relative 'gitlab_logger'
require_relative 'gitlab_access'
require_relative 'gitlab_lfs_authentication'
require_relative 'httpunix'

module HTTPHelper
  READ_TIMEOUT = 300

  def config
    @config ||= GitlabConfig.new
  end

  def base_host
    "#{config.gitlab_url}/api/v4"
  end

  def host
    "#{base_host}/internal"
  end

  def http_client_for(uri, options = {})
    http = if uri.is_a?(URI::HTTPUNIX)
             Net::HTTPUNIX.new(uri.hostname)
           else
             Net::HTTP.new(uri.host, uri.port)
           end

    http.read_timeout = options[:read_timeout] || read_timeout

    if uri.is_a?(URI::HTTPS)
      http.use_ssl = true
      http.cert_store = cert_store
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if config.http_settings['self_signed_cert']
    end

    http
  end

  def http_request_for(method, uri, params = {}, options = {}, headers = {})
    request_klass = method == :get ? Net::HTTP::Get : Net::HTTP::Post
    request = request_klass.new(uri.request_uri, headers)

    user = config.http_settings['user']
    password = config.http_settings['password']
    request.basic_auth(user, password) if user && password

    unless options[:include_secret_token] == false
      request.set_form_data(params.merge(secret_token: secret_token))
    end

    if options[:body]
      request.body = options[:body]
    end

    if uri.is_a?(URI::HTTPUNIX)
      # The HTTPUNIX HTTP client does not set a correct Host header. This can
      # lead to 400 Bad Request responses.
      request['Host'] = 'localhost'
    end

    request
  end

  def request(method, url, params = {}, options = {}, headers = {})
    $logger.debug('Performing request', method: method.to_s.upcase, url: url)

    uri = URI.parse(url)
    http = http_client_for(uri, options)
    request = http_request_for(method, uri, params, options, headers)

    begin
      start_time = Time.new
      response = http.start { http.request(request) }
    rescue => e
      $logger.warn('Failed to connect to internal API', method: method.to_s.upcase, url: url, error: e)
      raise ApiUnreachableError
    ensure
      $logger.info('finished HTTP request', method: method.to_s.upcase, url: url, duration: Time.new - start_time)
    end

    if response.code == "200"
      $logger.debug('Received response', code: response.code, body: response.body)
    else
      $logger.error('API call failed', method: method.to_s.upcase, url: url, code: response.code, body: response.body)
    end

    response
  end

  def get(url, options = {}, headers = {})
    request(:get, url, {}, options, headers)
  end

  def post(url, params, options = {}, headers = {})
    request(:post, url, params, options, headers)
  end

  def cert_store
    @cert_store ||= begin
      store = OpenSSL::X509::Store.new
      store.set_default_paths

      ca_file = config.http_settings['ca_file']
      store.add_file(ca_file) if ca_file

      ca_path = config.http_settings['ca_path']
      store.add_path(ca_path) if ca_path

      store
    end
  end

  def secret_token
    @secret_token ||= File.read config.secret_file
  end

  def read_timeout
    config.http_settings['read_timeout'] || READ_TIMEOUT
  end
end

# FIXME: Move somewhere logical
class CustomAction
  attr_reader :message

  def initialize(klass, opts, message)
    @klass = klass
    @opts = opts
    @message = message
  end

  def self.create_from_json(json_str)
    json = JSON.parse(json_str)
    data = json["data"]
    new(data["klass"], data["opts"], json["message"])
  end

  def klass_instance_execute(*args)
    Object.const_get(klass).new(*args, opts).execute
  end

  private

  attr_reader :klass, :opts
end

# FIXME: Move into EE
class GitPushSSHProxyToPrimary
  include HTTPHelper

  def initialize(*args, opts)
    @key_id = args.pop
    @opts = opts
  end

  def execute
    $stderr.puts "warning: proxying to #{url}"

    $stderr.puts base_headers

    return false unless info_refs_for_git_push(url, base_headers)

    git_push(url, base_headers, $stdin.read)
  end

  private

  attr_reader :key_id, :opts

  def geo_host
    "#{base_host}/geo"
  end

  def url
    @url ||= opts['redirect_to']
  end

  def username
    @username ||= opts['username']
  end

  def base_headers
    @base_headers ||= {
      'GL-Id' => key_id,
      'GL-Username' => username,
      'Authorization' => generate_geo_token
    }
  end

  def generate_geo_token
    resp = get("#{geo_host}/generate_token")
    JSON.parse(resp.body)['token'] rescue nil
  end

  def info_refs_for_git_push(url, headers)
    url = "#{url}/info/refs?service=git-receive-pack"
    headers['Content-Type'] = 'application/x-git-upload-pack-request'

    resp = get(url, { include_secret_token: false }, headers)

    unless resp.code == '200'
      $stderr.puts("error: #{resp.code} #{resp.body}")
      # FIXME: raise an exception here?
      return false
    end

    # HTTP(S) and SSH responses are vary similar, except for the snippet below
    # See Downloading Data > HTTP(S) section at https://git-scm.com/book/en/v2/Git-Internals-Transfer-Protocols
    trimmed_body = resp.body.gsub("001f# service=git-receive-pack\n0000", '')

    print trimmed_body
    STDOUT.flush
  end

  def git_push(base_url, headers, info_refs_response)
    url = "#{base_url}/git-receive-pack"
    headers = headers.merge(
      'Content-Type' => 'application/x-git-receive-pack-request',
      'Accept' => 'application/x-git-receive-pack-result'
    )

    resp = post(url, {}, { include_secret_token: false, body: info_refs_response }, headers)

    unless resp.code == '200'
      $stderr.puts("error: #{resp.code} #{resp.body}")
      # FIXME: raise an exception here?
      return false
    end

    print resp.body
    STDOUT.flush
  end
end

class GitlabNet # rubocop:disable Metrics/ClassLength
  include HTTPHelper

  class ApiUnreachableError < StandardError; end
  class NotFound < StandardError; end

  CHECK_TIMEOUT = 5

  def check_access(cmd, gl_repository, repo, actor, changes, protocol, env: {})
    changes = changes.join("\n") unless changes.is_a?(String)

    params = {
      action: cmd,
      changes: changes,
      gl_repository: gl_repository,
      project: sanitize_path(repo),
      protocol: protocol,
      env: env
    }

    if actor =~ /\Akey\-\d+\Z/
      params[:key_id] = actor.gsub("key-", "")
    elsif actor =~ /\Auser\-\d+\Z/
      params[:user_id] = actor.gsub("user-", "")
    end

    url = "#{host}/allowed"
    resp = post(url, params)

    case resp.code
    when '200'
      GitAccessStatus.create_from_json(resp.body)
    when '300'
      CustomAction.create_from_json(resp.body)
    else
      GitAccessStatus.new(false,
                          'API is not accessible',
                          gl_repository: nil,
                          gl_username: nil,
                          repository_path: nil,
                          gitaly: nil)
    end
  end

  def discover(key)
    key_id = key.gsub("key-", "")
    resp = get("#{host}/discover?key_id=#{key_id}")
    JSON.parse(resp.body) rescue nil
  end

  def lfs_authenticate(key, repo)
    params = {
      project: sanitize_path(repo),
      key_id: key.gsub('key-', '')
    }

    resp = post("#{host}/lfs_authenticate", params)

    if resp.code == '200'
      GitlabLfsAuthentication.build_from_json(resp.body)
    end
  end

  def pre_receive(gl_repository)
    resp = post("#{host}/pre_receive", gl_repository: gl_repository)

    raise NotFound if resp.code == '404'

    JSON.parse(resp.body) if resp.code == '200'
  end

  def post_receive(gl_repository, identifier, changes)
    params = {
      gl_repository: gl_repository,
      identifier: identifier,
      changes: changes
    }
    resp = post("#{host}/post_receive", params)

    raise NotFound if resp.code == '404'

    JSON.parse(resp.body) if resp.code == '200'
  end

  private

  def broadcast_message
    resp = get("#{host}/broadcast_message")
    JSON.parse(resp.body) rescue {}
  end

  def merge_request_urls(gl_repository, repo_path, changes)
    changes = changes.join("\n") unless changes.is_a?(String)
    changes = changes.encode('UTF-8', 'ASCII', invalid: :replace, replace: '')
    url = "#{host}/merge_request_urls?project=#{URI.escape(repo_path)}&changes=#{URI.escape(changes)}"
    url += "&gl_repository=#{URI.escape(gl_repository)}" if gl_repository
    resp = get(url)

    if resp.code == '200'
      JSON.parse(resp.body)
    else
      []
    end
  rescue
    []
  end

  def check
    get("#{host}/check", read_timeout: CHECK_TIMEOUT)
  end

  def authorized_key(key)
    resp = get("#{host}/authorized_keys?key=#{URI.escape(key, '+/=')}")
    JSON.parse(resp.body) if resp.code == "200"
  rescue
    nil
  end

  def two_factor_recovery_codes(key)
    key_id = key.gsub('key-', '')
    resp = post("#{host}/two_factor_recovery_codes", key_id: key_id)

    JSON.parse(resp.body) if resp.code == '200'
  rescue
    {}
  end

  def notify_post_receive(gl_repository, repo_path)
    params = { gl_repository: gl_repository, project: repo_path }
    resp = post("#{host}/notify_post_receive", params)

    resp.code == '200'
  rescue
    false
  end

  protected

  def sanitize_path(repo)
    repo.delete("'")
  end
end
