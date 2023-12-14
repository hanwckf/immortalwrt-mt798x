'use strict';
'require form';
'require network';
'require uci';
'require view';

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('eqos'),
			network.getHostHints()
		]);
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('eqos', _('EQoS'),
 			_('Network speed control service.(Compatiable with Mediatek HNAT)'));
 			
		s = m.section(form.NamedSection, 'config', 'eqos');

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		
		o = s.option(form.Flag, 'ipv6enabled', _('IPV6Enable'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, 'download', _('Download speed (Mbit/s)'),
			_('Total download bandwidth.'));
		o.datatype = 'and(uinteger,min(1))';
		o.rmempty = false;

		o = s.option(form.Value, 'upload', _('Upload speed (Mbit/s)'),
			_('Total upload bandwidth.'));
		o.datatype = 'and(uinteger,min(1))';
		o.rmempty = false;

		s = m.section(form.TableSection, 'device', _('Speed limit based on IP address(using unique comment less than 32 will enable hardware QOS)'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.enabled;
		
		o = s.option(form.Value, 'ip', _('IPV4 address'));
		o.datatype = 'ip4addr';
		for (var i of Object.entries(data[1]?.hosts))
			for (var v in i[1].ipaddrs)
				if (i[1].ipaddrs[v]) {
					var ip_addr = i[1].ipaddrs[v], ip_host = i[1].name;
					o.value(ip_addr, ip_host ? String.format('%s (%s)', ip_host, ip_addr) : ip_addr)
				}
		o.rmempty = false;
		
		var hosts = data[1]?.hosts;
		o = s.option(form.Value, 'mac', _('IPV6 host'));
		o.datatype = 'macaddr';
		Object.keys(hosts).forEach(function(mac) {
			var hint = hosts[mac].name || L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4)[0];
			o.value(mac, hint ? '%s (%s)'.format(mac, hint) : mac);
		});
		o.rmempty = true;

		o = s.option(form.Value, 'download', _('Download speed (kbit/s)'));
		o.datatype = 'and(uinteger,min(0))';
		o.rmempty = false;

		o = s.option(form.Value, 'upload', _('Upload speed (kbit/s)'));
		o.datatype = 'and(uinteger,min(0))';
		o.rmempty = false;

		o = s.option(form.Value, 'comment', _('Comment'));
		o.datatype = 'and(uinteger,min(1))';
		o.rmempty = false;

		return m.render();
	}
});
