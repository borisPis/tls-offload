.. -*- coding: utf-8; mode: rst -*-

.. _VIDIOC_SUBSCRIBE_EVENT:
.. _VIDIOC_UNSUBSCRIBE_EVENT:

******************************************************
ioctl VIDIOC_SUBSCRIBE_EVENT, VIDIOC_UNSUBSCRIBE_EVENT
******************************************************

Name
====

VIDIOC_SUBSCRIBE_EVENT - VIDIOC_UNSUBSCRIBE_EVENT - Subscribe or unsubscribe event


Synopsis
========

.. cpp:function:: int ioctl( int fd, int request, struct v4l2_event_subscription *argp )


Arguments
=========

``fd``
    File descriptor returned by :ref:`open() <func-open>`.

``request``
    VIDIOC_SUBSCRIBE_EVENT, VIDIOC_UNSUBSCRIBE_EVENT

``argp``


Description
===========

Subscribe or unsubscribe V4L2 event. Subscribed events are dequeued by
using the :ref:`VIDIOC_DQEVENT` ioctl.


.. _v4l2-event-subscription:

.. flat-table:: struct v4l2_event_subscription
    :header-rows:  0
    :stub-columns: 0
    :widths:       1 1 2


    -  .. row 1

       -  __u32

       -  ``type``

       -  Type of the event, see :ref:`event-type`.

	  .. note:: ``V4L2_EVENT_ALL`` can be used with
	     :ref:`VIDIOC_UNSUBSCRIBE_EVENT <VIDIOC_SUBSCRIBE_EVENT>` for
	     unsubscribing all events at once.

    -  .. row 2

       -  __u32

       -  ``id``

       -  ID of the event source. If there is no ID associated with the
	  event source, then set this to 0. Whether or not an event needs an
	  ID depends on the event type.

    -  .. row 3

       -  __u32

       -  ``flags``

       -  Event flags, see :ref:`event-flags`.

    -  .. row 4

       -  __u32

       -  ``reserved``\ [5]

       -  Reserved for future extensions. Drivers and applications must set
	  the array to zero.



.. _event-flags:

.. flat-table:: Event Flags
    :header-rows:  0
    :stub-columns: 0
    :widths:       3 1 4


    -  .. row 1

       -  ``V4L2_EVENT_SUB_FL_SEND_INITIAL``

       -  0x0001

       -  When this event is subscribed an initial event will be sent
	  containing the current status. This only makes sense for events
	  that are triggered by a status change such as ``V4L2_EVENT_CTRL``.
	  Other events will ignore this flag.

    -  .. row 2

       -  ``V4L2_EVENT_SUB_FL_ALLOW_FEEDBACK``

       -  0x0002

       -  If set, then events directly caused by an ioctl will also be sent
	  to the filehandle that called that ioctl. For example, changing a
	  control using :ref:`VIDIOC_S_CTRL <VIDIOC_G_CTRL>` will cause
	  a V4L2_EVENT_CTRL to be sent back to that same filehandle.
	  Normally such events are suppressed to prevent feedback loops
	  where an application changes a control to a one value and then
	  another, and then receives an event telling it that that control
	  has changed to the first value.

	  Since it can't tell whether that event was caused by another
	  application or by the :ref:`VIDIOC_S_CTRL <VIDIOC_G_CTRL>`
	  call it is hard to decide whether to set the control to the value
	  in the event, or ignore it.

	  Think carefully when you set this flag so you won't get into
	  situations like that.


Return Value
============

On success 0 is returned, on error -1 and the ``errno`` variable is set
appropriately. The generic error codes are described at the
:ref:`Generic Error Codes <gen-errors>` chapter.
