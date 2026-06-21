"""Publish approved IOCs to feeds integrations (MISP, DXL, HTTP push, ESA, vendors)."""
import logging


def publish_ioc_row(row, *, get_setting, audit_log=None, submission_method: str | None = None):
    """
    Run outbound distribution for an IOC row that is no longer pending_approval.
    Safe to call after admin approve or immediate analyst submit when auto-publish is on.
    """
    if row is None or getattr(row, 'pending_approval', False):
        return
    if getattr(row, 'revoked', False):
        return

    ioc_type = row.type
    value = row.value
    analyst = (row.analyst or '').strip().lower()
    ticket_id = row.ticket_id
    comment = row.comment
    exp_date = row.expiration_date
    campaign_id = row.campaign_id
    tags_json = row.tags or '[]'
    user_id = row.user_id
    method = submission_method or row.submission_method or 'single'

    if ioc_type == 'Hash':
        try:
            if get_setting('dxl_enabled', 'false').lower() == 'true':
                config_path = get_setting('dxl_config_path', '').strip()
                if config_path:
                    from utils.dxl_tie import push_hash_to_tie
                    dxl_ok = push_hash_to_tie(config_path, value, audit_log)
                    if not dxl_ok:
                        try:
                            from utils.integration_retry import enqueue_integration_retry
                            enqueue_integration_retry(
                                'dxl',
                                {'action': 'create', 'type': 'Hash', 'value': value},
                                'dxl_push_failed',
                                get_setting=get_setting,
                            )
                        except Exception:
                            logging.exception('DXL enqueue retry failed')
        except Exception as dxl_err:
            logging.warning('DXL push on publish_ioc_row failed: %s', dxl_err)

    misp_sync_user = (get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
    try:
        if get_setting('misp_push_enabled', 'false').lower() == 'true' and analyst != misp_sync_user:
            url = get_setting('misp_url', '').strip()
            api_key = get_setting('misp_api_key', '').strip()
            if url and api_key:
                verify_ssl = get_setting('misp_verify_ssl', 'false').lower() == 'true'
                include_comment = get_setting('misp_push_include_comment', 'true').lower() == 'true'
                event_id_str = get_setting('misp_push_default_event_id', '').strip()
                event_id = int(event_id_str) if event_id_str.isdigit() else None
                from utils.misp_push import push_ioc_to_misp
                cmt = (comment or '').strip() if comment else ''
                ok, msg = push_ioc_to_misp(
                    ioc_type, value, cmt or None,
                    event_id=event_id, url=url, api_key=api_key, verify_ssl=verify_ssl,
                    include_comment=include_comment,
                )
                if not ok:
                    logging.warning('MISP push on publish_ioc_row failed: %s', msg)
                    try:
                        from utils.integration_retry import enqueue_integration_retry, integration_is_retriable_failure
                        if integration_is_retriable_failure(msg):
                            enqueue_integration_retry(
                                'misp_push',
                                {'action': 'create', 'type': ioc_type, 'value': value, 'comment': cmt or None},
                                msg,
                                get_setting=get_setting,
                            )
                    except Exception:
                        logging.exception('MISP push enqueue retry failed')
    except Exception as misp_err:
        logging.warning('MISP push on publish_ioc_row failed: %s', misp_err)

    try:
        from flask import current_app
        from utils.ioc_push import schedule_ioc_push_after_create, ioc_context_from_submission
        from utils.outbound_ioc import schedule_auxiliary_vendor_integrations

        ctx = ioc_context_from_submission(
            ioc_type=ioc_type,
            value=value,
            analyst=analyst,
            ticket_id=ticket_id,
            comment=comment,
            expiration_date=exp_date,
            campaign_id=campaign_id,
            tags_json=tags_json,
            submission_method=method,
            user_id=user_id,
        )
        schedule_ioc_push_after_create(current_app._get_current_object(), ctx)
        schedule_auxiliary_vendor_integrations(current_app._get_current_object(), [ctx])
    except Exception as push_err:
        logging.warning('IOC HTTP/vendor push on publish_ioc_row failed: %s', push_err)

    try:
        from flask import current_app
        from utils.cisco_esa import schedule_esa_dictionary_after_submission
        schedule_esa_dictionary_after_submission(
            current_app._get_current_object(),
            ioc_type=ioc_type,
            value=value,
            analyst=analyst,
            ticket_id=ticket_id,
            comment=comment,
            expiration_date=exp_date,
            campaign_id=campaign_id,
            tags_json=tags_json,
            submission_method=method,
            user_id=user_id,
        )
    except Exception as esa_err:
        logging.warning('ESA on publish_ioc_row failed: %s', esa_err)
