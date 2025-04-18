from flask import Blueprint, jsonify
from app.models import Device, CounterHistory
from datetime import datetime, timedelta
from app import db

# Create blueprint with a URL prefix
graph_routes = Blueprint('graph_routes', __name__, url_prefix='')

@graph_routes.route('/get_graph_data/<int:device_id>/<int:int_id>', methods=['GET'])
def get_graph_data(device_id, int_id):
    try:
        history = CounterHistory.query.filter_by(device_id=device_id, interface_index=int_id)\
            .order_by(CounterHistory.timestamp.desc())\
            .limit(30)\
            .all()

        if len(history) < 2:
            return jsonify({
                'error': 'Not enough data points for rate calculation',
                'timestamps': [],
                'in_rates': [],
                'out_rates': []
            }), 200
        timestamps = []
        in_rates = []
        out_rates = []

        for i in range(len(history) - 1):
           
            current = history[i]
            previous = history[i + 1]
            time_diff = (current.timestamp - previous.timestamp).total_seconds()
            if time_diff == 0:
                continue
            in_delta = current.in_octets - previous.in_octets
            out_delta = current.out_octets - previous.out_octets

            # Wrap handling (32-bit)
            if in_delta < 0:
                in_delta += 2**32
            if out_delta < 0:
                out_delta += 2**32

            in_rate = (in_delta * 8) / time_diff
            out_rate = (out_delta * 8) / time_diff

            timestamps.append(current.timestamp.isoformat())
            in_rates.append(in_rate)
            out_rates.append(out_rate)

        

        return jsonify({
            'timestamps': timestamps[::-1],
            'in_rates': in_rates[::-1],
            'out_rates': out_rates[::-1]
        })

    except Exception as e:
        return jsonify({
            'error': f'Error retrieving graph data: {str(e)}',
            'timestamps': [],
            'in_rates': [],
            'out_rates': []
        }), 500
