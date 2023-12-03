/* Copyright (C) 2022 ImmortalWrt.org */

'use strict';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require view';

var getSystemFeatures = rpc.declare({
	object: 'luci.turboacc',
	method: 'getSystemFeatures',
	expect: { '': {} }
});

var getFastPathStat = rpc.declare({
	object: 'luci.turboacc',
	method: 'getFastPathStat',
	expect: { '': {} }
});

var getFullConeStat = rpc.declare({
	object: 'luci.turboacc',
	method: 'getFullConeStat',
	expect: { '': {} }
});

var getTCPCCAStat = rpc.declare({
	object: 'luci.turboacc',
	method: 'getTCPCCAStat',
	expect: { '': {} }
});

function getServiceStatus() {
	return Promise.all([
		L.resolveDefault(getFastPathStat(), {}),
		L.resolveDefault(getFullConeStat(), {}),
		L.resolveDefault(getTCPCCAStat(), {})
	]);
}

function renderStatus(stats) {
	var spanTemp = '<em><span style="color:%s"><strong>%s</strong></span></em>';
	var renderHTML = [];
	for (var stat of stats)
		if (stat.type) {
			if (stat.type.includes(' / ')) {
				var types = stat.type.split(' / ');
				var inner = spanTemp.format('green', types[0]);
				for (var i of types.slice(1))
					inner += spanTemp.format('none', ' / ') + spanTemp.format('red', i);
				renderHTML.push(inner);
			} else
				renderHTML.push(spanTemp.format('green', stat.type));
		} else
			renderHTML.push(spanTemp.format('red', _('Disabled')));
	return renderHTML;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('turboacc'),
			L.resolveDefault(getSystemFeatures(), {})
		]);
	},

	render: function(data) {
		var m, s, o;
		var features = data[1];

		m = new form.Map('turboacc', _('TurboACC settings'),
			_('Open source flow offloading engine (fast path or hardware NAT).'));

		s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(getServiceStatus()).then(function (res) {
					var stats = renderStatus(res);
					var tds = [ 'fastpath_state', 'fullcone_state', 'tcpcca_state' ];
					for (var i in tds) {
						var view = document.getElementById(tds[i]);
						view.innerHTML = stats[i];
					}
				});
			});

			return E('fieldset', { 'class': 'cbi-section' }, [
				E('legend', {}, _('Acceleration Status')),
				E('table', { 'class': 'table', 'width': '100%', 'cellspacing': '10' }, [
					E('tr', {}, [
						E('td', { 'width': '33%' }, _('FastPath Engine')),
						E('td', { 'id': 'fastpath_state' }, E('em', {}, _('Collecting data...')))
					]),
					E('tr', {}, [
						E('td', { 'width': '33%' }, _('Full Cone NAT')),
						E('td', { 'id': 'fullcone_state' }, E('em', {}, _('Collecting data...')))
					]),
					E('tr', {}, [
						E('td', { 'width': '33%' }, _('TCP CCA')),
						E('td', { 'id': 'tcpcca_state' }, E('em', {}, _('Collecting data...')))
					])
				])
			]);
		}

		/* Mark user edited */
		s = m.section(form.NamedSection, 'global', 'turboacc');
		o = s.option(form.HiddenValue, 'set');
		o.load = (/* ... */) => { return 1 };
		o.readonly = true;
		o.rmempty = false;

		s = m.section(form.NamedSection, 'config', 'turboacc');

		o = s.option(form.ListValue, 'fastpath', _('Fastpath engine'),
			_('The offloading engine for routing/NAT.'));
		o.value('disabled', _('Disable'));
		if (features.hasFLOWOFFLOADING)
			o.value('flow_offloading', _('Flow offloading'));
		if (features.hasFASTCLASSIFIER)
			o.value('fast_classifier', _('Fast classifier'));
		if (features.hasSHORTCUTFECM)
			o.value('shortcut_fe_cm', _('SFE connection manager'));
		if (features.hasMEDIATEKHNAT)
			o.value('mediatek_hnat', _('MediaTek HNAT'));
		o.default = 'disabled';
		o.rmempty = false;
		o.onchange = function(ev, section_id, value) {
			var desc = ev.target.nextElementSibling;
			if (value === 'flow_offloading')
				desc.innerHTML = _('Software based offloading for routing/NAT.');
			else if (value === 'fast_classifier')
				desc.innerHTML = _('Fast classifier connection manager for the shortcut forwarding engine.');
			else if (value === 'shortcut_fe_cm')
				desc.innerHTML = _('Simple connection manager for the shortcut forwarding engine.');
			else if (value === 'mediatek_hnat')
				desc.innerHTML = _('MediaTek\'s open source hardware offloading engine.');
			else
				desc.innerHTML = _('The offloading engine for routing/NAT.');
		}

		o = s.option(form.Flag, 'fastpath_fo_hw', _('Hardware flow offloading'),
			_('Requires hardware NAT support. Implemented at least for mt7621.'));
		o.default = o.disabled;
		o.rmempty = false;
		o.depends('fastpath', 'flow_offloading');

		o = s.option(form.Flag, 'fastpath_fc_br', _('Bridge Acceleration'),
			_('Enable bridge acceleration (may be functional conflict with bridge-mode VPN server).'));
		o.default = o.disabled;
		o.rmempty = false;
		o.depends('fastpath', 'fast_classifier');

		if (features.hasIPV6) {
			o = s.option(form.Flag, 'fastpath_fc_ipv6', _('IPv6 acceleration'),
				_('Enable IPv6 Acceleration.'));
			o.default = o.disabled;
			o.rmempty = false;
			o.depends('fastpath', 'fast_classifier');
		}

		o = s.option(form.Flag, 'fastpath_mh_eth_hnat', _('Enable ethernet HNAT'),
			_('Enable hardware offloading for wired connections.'));
		o.default = o.enabled;
		o.rmempty = false;
		o.depends('fastpath', 'mediatek_hnat');

		o = s.option(form.Flag, 'fastpath_mh_eth_hnat_v6', _('Enable ethernet IPv6 HNAT'),
			_('Enable hardware offloading for wired IPv6 connections.'));
		o.default = o.enabled;
		o.rmempty = false;
		o.depends('fastpath_mh_eth_hnat', '1');

		o = s.option(form.ListValue, 'fullcone', _('Full cone NAT'),
			_('Full cone NAT (NAT1) can improve gaming performance effectively.'));
		o.value('0', _('Disable'))
		if (features.hasXTFULLCONENAT)
			o.value('1', _('xt_FULLCONENAT'));
		o.value('2', _('Boardcom fullcone'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.ListValue, 'tcpcca', _('TCP CCA'),
			_('TCP congestion control algorithm.'));
		for (var i of features.hasTCPCCA.split(' ').sort())
			o.value(i);
		o.default = 'cubic';
		o.rmempty = false;

		return m.render();
	}
});
