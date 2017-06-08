require 'active_record'
require 'active_record/log_subscriber'
require 'active_support/concern'
require 'active_support/lazy_load_hooks'

module AttrEncryptedPgcrypto
  module LogSubscriber
    module PostgresPgp
      # Public: Prevents sensitive data from being logged
      def sql(event)
        filter = /(pgp_sym_(encrypt|decrypt))\(((.|\n)*?)\)/i

        event.payload[:sql] = event.payload[:sql].gsub(filter) do |_|
          "#{$1}([FILTERED])"
        end

        super event
      end
    end
  end
end

ActiveSupport.on_load :attr_encrypted_pgcrypto_posgres_pgp_log do
  ActiveRecord::LogSubscriber.send :prepend, AttrEncryptedPgcrypto::LogSubscriber::PostgresPgp
end
