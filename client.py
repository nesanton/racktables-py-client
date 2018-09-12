#!/bin/env python
# -*- coding: utf-8 -*-

import re
import json
import base64
import urllib
import urllib2
import logging

module_logger = logging.getLogger('racktables_client')

class RacktablesClient:

    def __init__(self, api, username=None, password=None):

        self.logger = logging.getLogger('racktables_client')
        self.logger.debug('using API base URI of %s', api)
        self.api = api
        self.chapter_cache   = {}
        self.tags_list_cache = None
        self.auth_string = base64.b64encode('%s:%s' % (username, password))


    def get_objects(self, alt_key=None, include_attrs=False, type_filter=None, tag_filter=[]):
        "Returns a dictionary of all the objects in Racktables."

        args = {}

        # include attributes if requested
        if include_attrs:
            args['include_attrs'] = 1

        # if types or tags were specified, create the necessary parameters
        if tag_filter:
            tag_ids = self.get_tag_ids(tag_filter)
            args['cft[]'] = tag_ids

        if type_filter:
            args['cfe'] = '{{$typeid_{0}}}'.format(int(type_filter))

        # TODO: attributes, which also uses cfe (and if both are set, or more than one attr
        #       is set, the paramter name must include braces: cfe[])
        #       format for specifying attributes is: cfe={$attr_<ATTR_ID>_<ATTR_VALUE>}

        if args:
            args['andor'] = 'and'

        objects = {}
        raw_objects = self.make_request('get_depot', args, response_only=False)

        if alt_key is not None:
            for object_id, object_data in raw_objects.items():
                objects[object_data[alt_key]] = object_data
        else:
            objects = raw_objects

        return objects


    def get_object(self, object_id, get_attrs=False, get_unset_attrs=False):
        "Returns an object in Racktables."

        rt_object = {}
        args      = {'object_id': object_id}

        if get_attrs:
            args['include_attrs'] = 1

        if get_unset_attrs:
            args['include_unset_attrs'] = 1

        rt_object = self.make_request('get_object', args)

        return rt_object


    def add_object_log(self, object_id, logentry):
        self.make_request('add_object_log', {'object_id': object_id, 'logentry': logentry})


    def add_object(self, object_name,
                   object_asset_no=None,
                   object_label=None,
                   object_type_id=4,
                   object_comment=None,
                   taglist=[],
                   attrs={}):
        "Adds a new object to Racktables. The only required parameter is the object name."

        args = { 'object_name':     object_name,
                 'object_type_id':  object_type_id, }

        # only include label and asset number in the url args if they're defined
        if object_asset_no is not None:
            args['object_asset_no'] = object_asset_no

        if object_label is not None:
            args['object_label'] = object_label

        new_rt_object    = self.make_request('add_object', args)
        if not new_rt_object:
            return None
        new_rt_object_id = new_rt_object['id']

        self.logger.info('created new object, id: %s', new_rt_object_id)

        # add any attrs or comment
        if object_comment or attrs:
            self.logger.info('adding comment/attributes for new object id %s', new_rt_object_id)
            self.edit_object(object_id       = new_rt_object_id,
                             object_name     = object_name,
                             object_asset_no = object_asset_no,
                             object_label    = object_label,
                             object_type_id  = object_type_id,
                             object_comment  = object_comment,
                             attrs           = attrs)

        # add tags if specified
        if taglist:
            self.logger.info('adding tags for new object id %s', new_rt_object_id)
            self.update_object_tags(new_rt_object_id, taglist)

        return new_rt_object


    def edit_object(self, object_id,
                    object_name='',
                    object_asset_no='',
                    object_label='',
                    object_type_id=4,
                    object_comment='',
                    attrs={}):
        "Edits an existing object in Racktables. Attributes not passed will be erased."

        # get rid of explicitly-passed "None" values for core attributes because
        # urllib.urlencode() will turn them into the string 'None'
        if object_name is None:
            object_name = ''

        if object_asset_no is None:
            object_asset_no = ''

        if object_label is None:
            object_label = ''

        if object_comment is None:
            object_comment = ''

        args = { 'object_id':       object_id,
                 'object_type_id':  object_type_id,
                 'object_name':     object_name,
                 'object_asset_no': object_asset_no,
                 'object_label':    object_label,
                 'object_comment':  object_comment }

        # add attributes passed by ID
        for attr_id, attr_value in attrs.items():
            args['attr_' + str(attr_id)] = attr_value

        updated_object = self.make_request('edit_object', args)

        return updated_object

    def edit_object_safe(self, object_id, append_comment=True, **kwargs):
        "Edits an existing object in Racktables. Attributes not passed WILL NOT be erased."

        # remove values explicitly set to None
        kwargs = {k: v for k, v in kwargs.iteritems() if v is not None}
        obj = self.get_object(object_id)

        args = { 'object_id':       object_id,
                 'object_type_id':  kwargs.get('object_type_id', obj['objtype_id']),
                 'object_name':     kwargs.get('object_name', obj['name']),
                 'object_asset_no': kwargs.get('object_asset_no', obj['asset_no']),
                 'object_label':    kwargs.get('object_label', obj['label']),
                 'object_comment':  kwargs.get('object_comment', obj['comment']),
                 'attrs':           kwargs.get('attrs', {})}

        if append_comment and obj['comment']:
            new_comment = kwargs.get('object_comment', '')
            if new_comment:
                args['object_comment'] = obj['comment'] + '\n\n' + new_comment

        return self.edit_object(**args)

    def delete_object(self, object_id):
        "Deletes one object from Racktables."

        success = False

        # API responds with depot after deletion
        depot = self.make_request('delete_object', {'object_id': object_id})
        if object_id not in depot:
            success = True

        return success


    def add_object_ipv4_address(self, object_id, ip_address, os_interface):
        "Add an IPv4 address to an object."

        success = False

        # response is the get_object page
        updated_object = self.make_request('add_object_ip_allocation', {'object_id': object_id,
                                                                       'ip':        ip_address,
                                                                       'bond_name': os_interface})
        if updated_object:
            ip_addresses = map(lambda address: address['addrinfo']['ip'], updated_object['ipv4'].values())
        else:
            return success

        if ip_address in ip_addresses:
            self.logger.info('updated object id %s interface %s to IP address %s',
                        object_id, os_interface, ip_address)
            success = True

        return success


    def edit_object_ipv4_address(self, object_id, ip_address, os_interface):
        "Add an IPv4 address to an object."

        success = False

        # response is the get_object page
        updated_object = self.make_request('edit_object_ip_allocation', {'object_id': object_id,
                                                                         'ip':        ip_address,
                                                                         'bond_name': os_interface})
        if updated_object:
            ip_addresses = {a['addrinfo']['ip']: a['osif'] for a in updated_object['ipv4'].values()}
        else:
            return success

        if ip_address in ip_addresses:
            self.logger.info('updated object id %s interface %s to IP address %s',
                        object_id, os_interface, ip_address)
            if ip_addresses[ip_address] == os_interface:
                success = True
        return success


    def delete_object_ipv4_address(self, object_id, ip_address):
        "Delete an IPv4 address from an object."

        success = False

        # response is the get_object page
        updated_object = self.make_request('delete_object_ip_allocation', {'object_id': object_id,
                                                                           'ip':        ip_address})
        if updated_object:
            remaining_ips = map(lambda address: address['addrinfo']['ip'], updated_object['ipv4'].values())
        else:
            return success

        if ip_address not in remaining_ips:
            self.logger.info('removed IP address %s from object id %s',
                             ip_address, object_id)
            success = True

        return success


    def add_object_port(self, object_id, name, mac_address, port_type_id='1-24', label=''):
        "Add a port (eth0, etc) to an object."

        new_port_id = None

        # capture raw response so we can look for the new port_id
        response = self.make_request('add_port', {'object_id': object_id,
                                                  'port_name': name,
                                                  'port_l2address': mac_address,
                                                  'port_label': label,
                                                  'port_type_id': port_type_id}, False)

        if 'port_id' in response['metadata']:
            new_port_id = response['metadata']['port_id']
            self.logger.info('added new port %s (id: %s) for object id %s, MAC address %s',
                             name, new_port_id, object_id, mac_address)

        return new_port_id


    def delete_object_port(self, object_id, port_id):
        "Delete a port from an object."

        success = False

        # response is the get_object page
        updated_object = self.make_request('delete_port', {'object_id': object_id,
                                                           'port_id':   port_id})

        remaining_ports = map(lambda port: port['id'], updated_object['ports'].values())

        if port_id not in remaining_ports:
            self.logger.info('removed port id %s from object id %s',
                             port_id, object_id)
            success = True

        return success


    def update_object_port(self, object_id, port_id, port_name,
                           port_label, port_l2address, port_reservation_comment, port_type_id='1-24'):
        success = False
        updated_object = self.make_request('update_port',
                                           {'object_id': object_id,
                                            'port_id':   port_id,
                                            'port_name': port_name,
                                            'port_type_id': port_type_id,
                                            'port_label': port_label,
                                            'port_l2address': port_l2address,
                                            'port_reservation_comment': port_reservation_comment})
        for port in updated_object['ports'].values():
            if port['id'] == port_id:
                if port['name'] == port_name and \
                   port['label'] == port_label and \
                   port['l2address'].lower() == port_l2address.lower() and \
                   port['reservation_comment'] == port_reservation_comment:
                    success = True
        return success


    def link_port(self, port_id, remote_port_id, cable_id=''):
        "Link two ports together."

        success = False

        # capture the raw response so we can look for the success metadata
        response = self.make_request('link_port', {'port':        port_id,
                                                   'remote_port': remote_port_id,
                                                   'cable':       cable_id}, False)

        if 'local_port' in response['metadata']:
            self.logger.info('linked port %s (object id %s) to remote port %s (object id %s)',
                             response['metadata']['local_port'],  response['metadata']['local_object'],
                             response['metadata']['remote_port'], response['metadata']['remote_object'])
            success = True

        return success


    def unlink_port(self, port_id):
        "Unlink a port."

        success = False

        # capture the raw response so we can look for the success metadata
        response = self.make_request('unlink_port', {'port_id': port_id}, False)

        if 'port_id' in response['metadata']:
            self.logger.info('unlinked port %s successfully', response['metadata']['port_id'])
            success = True

        return success


    def get_object_allocation(self, object_id):
        "Returns an object's physical allocation."

        allocation = {}
        raw_allocation = self.make_request('get_object_allocation', {'object_id': object_id})

        allocation['zerou_racks'] = []
        allocation['racks']       = {}

        # API returns all rack allocation data for each rack the item is installed in.
        # we just want to return a data structure like: {'<RACK_ID>': '<POSITION>': {0: 'T', 1: 'T', 2: 'T'},
        #                                                             '<POSITION>': {0: 'T', 1: 'T', 2: 'T'}, }
        for rack_id, rack_data in raw_allocation['racks'].items():

            # physical allocations for this object within this rack (if any: might be just zero-u mounted)
            rack_alloc = {}

            for key, value in rack_data.items():
                m = re.search('^\d+$', key)

                # found allocation data for a position in the rack
                if m is not None:
                    position = int(key)

                    idxes = {}

                    for idx, atom_data in value.items():
                        if 'object_id' in atom_data and int(atom_data['object_id']) == int(object_id):
                            idxes[int(idx)] = atom_data['state']

                    if idxes:
                        rack_alloc[position] = idxes


            # if the object had allocations, add the rack
            if rack_alloc:
                allocation['racks'][int(rack_id)] = rack_alloc


        # turn zero-u allocations into a simple list
        if raw_allocation['zerou_racks']:
            allocation['zerou_racks'] = map(lambda n: int(n), raw_allocation['zerou_racks'].values())

        return allocation


    def update_object_allocation(self, object_id, racks={}, zerou_racks=[]):
        "Sets an object's allocation. Pre-existing allocations are removed."

        allocs_list = []

        for rack_id, rack_alloc in racks.items():
            for position, idxes in rack_alloc.items():
                for idx in idxes:
                    allocs_list.append('atom_{0}_{1}_{2}'.format(rack_id, position, idx))

        for rack_id in zerou_racks:
            allocs_list.append('zerou_{0}'.format(rack_id))

        return self.make_request('update_object_allocation', {'object_id':     object_id,
                                                              'allocate_to[]': allocs_list})


    def link_entities(self, child_id, parent_id, child_type='object', parent_type='object'):
        "Links two entities, such as Hypervisor -> VM or Server chassis -> server."

        self.logger.debug('linking object id %s (%s, child) to object id %s (%s, parent)',
                          child_id, child_type, parent_id, parent_type)

        return self.make_request('link_entities', {'child_entity_type':  child_type,
                                      'child_entity_id':    child_id,
                                      'parent_entity_type': parent_type,
                                      'parent_entity_id':   parent_id})


    def get_tags(self, as_tree=False, use_cache=True):
        "Gets user-defined tags, as a list or optionally as a tree."

        tags = {}

        if as_tree:
            self.logger.debug('getting tags as a tree (never cached)')
            tags = self.make_request('get_tagtree')

        else:
            self.logger.debug('getting tags as a list')

            if self.tags_list_cache is None:
                self.logger.debug('initializing tag list cache')
                self.tags_list_cache = self.make_request('get_taglist')

            elif not use_cache:
                self.logger.debug('refreshing tag list cache by request')
                self.tags_list_cache = self.make_request('get_taglist')

            else:
                self.logger.debug('using previously cached version of tag list')

            tags = self.tags_list_cache

        return tags


    def get_tag_ids(self, tag_names=[]):
        "Converts a list of tags to a list of tag IDs."

        tag_ids = []

        # get the list of tags
        site_tags = self.get_tags(use_cache=False)

        for tag_name in tag_names:
            self.logger.debug('determining tag id for tag "%s"', tag_name)

            found = False
            for tagdata in site_tags.values():
                if tagdata['tag'] == tag_name:
                    tag_id = int(tagdata['id'])
                    self.logger.debug('tag "%s" has id %s', tag_name, tag_id)
                    tag_ids.append(tag_id)
                    found = True
                    break

            if not found:
                raise RacktablesClientException('no such tag "{0}"'.format(tag_name))

        return tag_ids


    def update_object_tags(self, object_id, new_tags=[]):
        "Updates an object's tags, which are given by name, not ID."

        tag_ids = self.get_tag_ids(new_tags)

        self.logger.debug('applying the following tags ids to object id %s: %s', object_id, str(tag_ids))

        return self.make_request('update_object_tags', {'object_id': object_id,
                                                        'taglist[]': tag_ids})

            
    def get_ipv4space(self):
        "Returns a dictionary containing top-level network data."

        return self.make_request('get_ipv4space')


    def get_ipv4network(self, network_id):
        "Returns a dictionary containing data for a single network."

        return self.make_request('get_ipv4network', {'network_id': network_id})


    def get_rackspace(self, key='row_id'):
        "Returns a dictionary containing all the rackspace rows. Default is to key the dictionary on the row IDs."

        rows = {}

        for row in self.make_request('get_rackspace').values():
            rows[row[key]] = row

        return rows


    def get_rack(self, rack_id):
        "Returns a dictionary containing data for a rack."

        return self.make_request('get_rack', {'rack_id': rack_id})


    def get_chapter(self, chapter_id, use_cache=True, raw_values=False):
        "Returns a 'chapter' from Racktables. Chapter data is cached in memory unless explicitly overridden."

        chapter = {}

        args = {'chapter_no': chapter_id}

        chapter_cache_key = chapter_id
        if raw_values:
            args['style'] = 'o'
            chapter_cache_key = '{0}.raw'.format(chapter_id)

        # not in the cache, get and store it
        if chapter_cache_key not in self.chapter_cache:
            self.logger.debug('fetching and cacheing chapter %s from API', chapter_id)
            chapter = self.make_request('get_chapter', args)
            self.chapter_cache[chapter_cache_key] = chapter

        # in cache and we can use it
        elif use_cache:
            self.logger.debug('using cached data for chapter %s', chapter_id)
            chapter = self.chapter_cache[chapter_cache_key]

        # in cache, but we want a fresh version. replace the cached version as well
        else:
            self.logger.debug('replacing cached data for chapter %s', chapter_id)
            chapter = self.make_request('get_chapter', args)
            self.chapter_cache[chapter_cache_key] = chapter

        return chapter


    def add_chapter_entry(self, chapter_id, value):
        "Add a value to chapter with chapter_id"

        # capture raw response so we can look for the new chapter_no
        entry_id = self.make_request('add_chapter_entry', {'chapter_no': chapter_id,
                                                'dict_value': value})['entry_id']

        self.logger.info('added new entry %s (id %s) to chapter id %s' % (value,
                                                                          entry_id,
                                                                          chapter_id))
        return entry_id


    def add_tag(self, tag_name):
        "Add a value to chapter with chapter_id"

        # capture raw response so we can look for the new chapter_no
        tag_id = self.make_request('add_tag', {'tag_name': tag_name})['tag_id']

        self.logger.info('added new tag %s with id %s' % (tag_name, tag_id))
        return tag_id


    def get_attributes(self):
        return self.make_request('get_attributes', {})


    def get_chapter_entry_id(self, chapter_id, value):
        for k, v in self.get_chapter(chapter_id, raw_values=True).iteritems():
            if v == value:
                return k
        return None


    def search(self, term):
        return self.make_request('search', {'term': term}, False)


    def make_request(self, method, args=None, response_only=True):

        # method first
        request_uri = self.api + "?method=" + method

        # add any additional parameters
        if args is not None:
            params = urllib.urlencode(args, doseq=True)
            request_uri += '&{params}'.format(params=params)

        self.logger.debug('requesting: {url}'.format(url=request_uri))
        request = urllib2.Request(request_uri)
        request.add_header("Authorization", "Basic {auth}".format(auth=self.auth_string))
        result = urllib2.urlopen(request)
        http_body = result.read()
        # ret_code = result.getcode()
        decoded = json.loads(http_body)

        # TODO: some error handling here
        if response_only:
            return decoded['response']
        else:
            return decoded


# TODO: actually implement this class somewhere else
class RacktablesObject:
    def __init__(self, object_id, type_id, name=None, asset_no=None,
                 rack_id=None, container_id=None, container_name=None,
                 has_problems=False,
                 comment=None,
                 attrs={},
                 etags={},
                 ipv4={},
                 ports={}):

        # TODO: check that *_id values are integers?
        self.object_id = object_id
        self.type_id   = type_id
        self.asset_no  = asset_no

        # TODO: handle allocation (zero-U, etc): rack_id, container_id, container_name

        self.has_problems = has_problems
        self.comment      = comment

        self.attrs = attrs
        self.etags = etags
        self.ipv4  = ipv4
        self.ports = ports


class RacktablesClientException(Exception):
    "Exception raised when something goes wrong with an interaction with Racktables."

    def __init__(self, message):
        self.message = message
